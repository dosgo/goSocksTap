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
		//start := time.Now()
		isExclude = isPortOwnedByPID(c.RemoteAddr().(*net.TCPAddr).Port, socksTap.socksServerPid)
		//elapsed := time.Since(start)
		//log.Printf("isPortOwnedByPID took %s", elapsed)
	}
	if socksTap.localSocks != "" && socksTap.socksClient != nil && comm.IsProxyRequiredFast(addrs[0]) && !isExclude {
		domain, ok := socksTap.dnsRecords.Get(addrs[0])
		if ok {
			log.Printf("domain: %s\r\n", domain)
			targetStr = net.JoinHostPort(strings.TrimSuffix(domain, "."), addrs[1])
		} else {
			fmt.Printf("no domain remoteAddr:%s\r\n", targetStr)
		}
		targetConn, err = socksTap.socksClient.Dial("tcp", targetStr)
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

func isPortOwnedByPID(srcPort int, targetPid int) bool {
	// 1. 预先构造端口搜索特征 (例如 ":0050")
	hexPortSuffix := fmt.Sprintf(":%04X", srcPort)

	// 2. 扫描目标进程的 FD，获取它持有的所有 Socket Inode
	// 这一步通常非常快，因为 FD 数量有限
	fdPath := fmt.Sprintf("/proc/%d/fd", targetPid)
	fds, err := os.ReadDir(fdPath)
	if err != nil {
		return false
	}

	targetInodes := make(map[string]struct{})
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		// 提取 socket:[12345] 中的 12345
		inode := link[8 : len(link)-1]
		targetInodes[inode] = struct{}{}
	}

	if len(targetInodes) == 0 {
		return false
	}

	// 3. 仅当进程持有 Socket 时，才去解析 TCP 表
	files := []string{"/proc/net/tcp", "/proc/net/tcp6"}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			// 快速过滤：如果这一行不包含我们的端口，直接跳过，不用做 Fields 分割
			if !strings.Contains(line, hexPortSuffix) {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) < 10 {
				continue
			}

			// 匹配本地端口且 Inode 在该进程的 map 中
			// fields[1] 是 local_address, fields[9] 是 inode
			if strings.HasSuffix(fields[1], hexPortSuffix) {
				if _, ok := targetInodes[fields[9]]; ok {
					f.Close()
					return true
				}
			}
		}
		f.Close()
	}

	return false
}
