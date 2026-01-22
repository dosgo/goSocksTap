//go:build !windows
// +build !windows

package socksTap

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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
		isExclude = getProcessBySrcPort(c.RemoteAddr().(*net.TCPAddr).Port, socksTap.socksServerPid)
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

func getProcessBySrcPort(srcPort int, pid int) bool {
	// 1. 构造十六进制端口后缀，例如 ":0050"
	hexPortSuffix := fmt.Sprintf(":%04X", srcPort)

	// 2. 需要检查的文件列表（支持 IPv4 和 IPv6）
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}

	foundInodes := make(map[string]struct{})
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}
			// local_address 是 fields[1]
			if strings.HasSuffix(fields[1], hexPortSuffix) {
				foundInodes[fields[9]] = struct{}{}
			}
		}
		f.Close()
	}
	if len(foundInodes) == 0 {
		fmt.Printf("foundInodes not\r\n")
		return false
	}

	// 3. 检查特定 PID 是否持有这些 Inode
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return false
	}

	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
		if err != nil {
			continue
		}
		for inode := range foundInodes {
			if link == "socket:["+inode+"]" {
				return true
			}
		}
	}
	return false
}
