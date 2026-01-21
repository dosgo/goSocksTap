//go:build !windows
// +build !windows

package socksTap

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/forward"
	"golang.org/x/sys/unix"
)

func (socksTap *SocksTap) handleConnection(c net.Conn) {
	defer c.Close()
	var targetConn net.Conn
	var err error
	targetStr, err := getOriginalDst(c.(*net.TCPConn))
	if err != nil {
		return
	}
	addrs := strings.Split(targetStr, ":")
	isExclude := false
	if socksTap.socksServerPid != 0 {
		_pid, _, _ := getProcessBySrcPort(socksTap.socksServerPid)
		if _pid == socksTap.socksServerPid {
			isExclude = true
		}
	}
	if socksTap.localSocks != "" && socksTap.dialer != nil && comm.IsProxyRequiredFast(addrs[0]) && !isExclude {
		domain, ok := socksTap.dnsRecords.Get(addrs[0])
		if ok {
			log.Printf("domain: %s\r\n", domain)
			targetStr = net.JoinHostPort(strings.TrimSuffix(domain, "."), addrs[1])
		} else {
			fmt.Printf("no domain remoteAddr:%s\r\n", targetStr)
		}
		targetConn, err = socksTap.dialer.Dial("tcp", targetStr)
	} else {
		fmt.Printf("targetStr:%s\r\n", targetStr)
		targetConn, err = dialer.Dial("tcp", targetStr)
	}
	if err != nil {
		return
	}
	defer targetConn.Close()

	// 双向转发
	go io.Copy(targetConn, c)
	io.Copy(c, targetConn)
}

var dialer = &net.Dialer{
	Timeout: 5 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			// 给代理发出的包打上 0x1A 标记，避免被 iptables 再次拦截
			err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, forward.GetMark())
			if err != nil {
				log.Printf("设置 SO_MARK 失败: %v", err)
			}
		})
	}}

func getDialer() *net.Dialer {
	return dialer
}

func getOriginalDst(conn net.Conn) (string, error) {
	tcpConn := conn.(*net.TCPConn)
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr string
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		// 获取 REDIRECT 之前的原始目的地
		originalAddr, err := unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, unix.SO_ORIGINAL_DST) // 80 = SO_ORIGINAL_DST
		if err != nil {
			controlErr = err
			return
		}
		// 解析 originalAddr 得到 IP 和端口...
		ip := net.IPv4(
			originalAddr.Multiaddr[4],
			originalAddr.Multiaddr[5],
			originalAddr.Multiaddr[6],
			originalAddr.Multiaddr[7],
		)
		port := binary.BigEndian.Uint16(originalAddr.Multiaddr[2:4])
		addr = fmt.Sprintf("%s:%d", ip.String(), port)
	})

	if controlErr != nil {
		return "", controlErr
	}
	return addr, err
}

func getProcessBySrcPort(srcPort int) (pid int, comm string, err error) {
	// 1. 寻找端口对应的 Inode
	inode := ""
	data, _ := os.ReadFile("/proc/net/tcp")
	lines := strings.Split(string(data), "\n")

	// 查找 16 进制端口号 (例如 80 端口是 0050)
	hexPort := fmt.Sprintf(":%04X", srcPort)
	for _, line := range lines {
		if strings.Contains(line, hexPort) {
			fields := strings.Fields(line)
			if len(fields) > 9 {
				inode = fields[9]
				break
			}
		}
	}

	if inode == "" || inode == "0" {
		return 0, "", fmt.Errorf("未找到 Inode")
	}

	// 2. 遍历 /proc 找到对应的 PID
	target := "socket:[" + inode + "]"
	files, _ := os.ReadDir("/proc")
	for _, f := range files {
		// 只看数字名称的目录 (PID)
		pidNum, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		// 检查该进程下的所有文件描述符 (fd)
		fdPath := fmt.Sprintf("/proc/%d/fd", pidNum)
		fds, _ := os.ReadDir(fdPath)
		for _, fd := range fds {
			link, _ := os.Readlink(filepath.Join(fdPath, fd.Name()))
			if link == target {
				// 3. 找到 PID，读取进程名
				commData, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pidNum))
				return pidNum, strings.TrimSpace(string(commData)), nil
			}
		}
	}
	return 0, "", fmt.Errorf("未找到进程")
}
