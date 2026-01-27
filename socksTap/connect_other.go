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
		isExclude = isPortOwnedByPID(c.RemoteAddr().(*net.TCPAddr).Port, socksTap.socksServerPid, false)
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

func isPortOwnedByPID(srcPort int, targetPid int, udp bool) bool {
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
	if udp {
		files = []string{"/proc/net/udp", "/proc/net/udp6"}
	}
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
					fmt.Printf("111\r\n")
					return true
				}
			}
		}
		f.Close()
	}
	return false
}
func isPortBelongsToApp(port int, pid int) bool {
	// 1. 获取目标进程所有的 Socket Inodes
	targetInodes := make(map[string]bool)
	fdPath := fmt.Sprintf("/proc/%d/fd", pid)
	fds, _ := os.ReadDir(fdPath)
	for _, fd := range fds {
		link, _ := os.Readlink(filepath.Join(fdPath, fd.Name()))
		if strings.HasPrefix(link, "socket:[") {
			inode := link[8 : len(link)-1]
			targetInodes[inode] = true
		}
	}

	// 2. 直接查找 /proc/net/udp，匹配 Inode
	// 这样比匹配端口更准确，因为 Inode 是唯一的 ID
	data, _ := os.ReadFile("/proc/net/udp")
	lines := strings.Split(string(data), "\n")
	hexPort := fmt.Sprintf(":%04X", port)

	for _, line := range lines {
		if strings.Contains(line, hexPort) {
			fields := strings.Fields(line)
			if len(fields) > 9 {
				inode := fields[9]
				if targetInodes[inode] {
					return true
				}
			}
		}
	}
	return false
}

func (socksTap *SocksTap) handleUDPData(localConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	addrInfo := socksTap.udpNat.GetAddrFromVirtualPort(uint16(clientAddr.Port))
	if addrInfo == nil {
		fmt.Printf("no origPort clientAddr.Port:%d\r\n", clientAddr.Port)
		return
	}
	origPort := addrInfo.DstPort
	fmt.Printf("handleUDPData\r\n")
	vPortKey := fmt.Sprintf("udp:%d", clientAddr.Port)
	// 检查这个“客户端”是否已经有对应的“转发隧道”了
	conn, ok := socksTap.udpClients.Load(vPortKey)
	if !ok {

		var proxyConn net.Conn
		var err error
		remoteAddr := net.JoinHostPort(clientAddr.IP.String(), strconv.Itoa(int(origPort)))
		// 如果没有，就 Dial 一个（类似于 TCP 的 Accept 过程）
		// 这里的 dialer 就是你之前配置的带 SO_MARK 的 socks5.Dialer
		fmt.Printf("socksTap.socksServerPid:%d\r\n", socksTap.socksServerPid)
		fmt.Printf("clientAddr.Port:%d\r\n", clientAddr.Port)
		if socksTap.localSocks != "" && socksTap.socksClient != nil && !isPortBelongsToApp(int(clientAddr.Port), socksTap.socksServerPid) {
			domain, ok := socksTap.dnsRecords.Get(clientAddr.IP.String())
			if ok {
				//log.Printf("domain: %s\r\n", domain)
				remoteAddr = net.JoinHostPort(strings.TrimSuffix(domain, "."), strconv.Itoa(int(origPort)))
				fmt.Printf("domain:%s\r\n", remoteAddr)
			} else {
				fmt.Printf("udp no domain remoteAddr:%s\r\n", remoteAddr)
			}

			conn, err := socksTap.socksClient.Dial("udp", remoteAddr)
			if err != nil {
				fmt.Printf("udp err:%+v\r\n", err)
				return
			}

			proxyConn = conn

		} else {
			// 模拟转发（如果不走 SOCKS5，直接 NAT）：
			proxyConn, err = dialer.Dial("udp", remoteAddr)
			if err != nil {
				fmt.Printf("udp err:%+v\r\n", err)
				return
			}
		}
		// 启动一个协程专门负责这个“连接”的回包（像 TCP 处理一样）
		go func(c net.Conn, addr *net.UDPAddr) {
			defer c.Close()
			defer socksTap.udpClients.Delete(vPortKey)
			resp := make([]byte, 2048)
			for {
				c.SetReadDeadline(time.Now().Add(time.Second * 60))
				rn, err := c.Read(resp)
				if err != nil {
					return
				} // 这里不需要 ReadFrom，因为它已经“连”上了
				localConn.WriteToUDP(resp[:rn], addr) // 发回给客户端
			}
		}(proxyConn, clientAddr)
		socksTap.udpClients.Store(vPortKey, proxyConn)
		conn = proxyConn
	}
	// 像 TCP 写入一样简单
	conn.(net.Conn).Write(data)
}

func (socksTap *SocksTap) startLocalUDPRelay() {
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", socksTap.proxyPort))
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDP 代理监听失败: %v", err)
	}
	defer conn.Close()

	log.Printf("UDP Relay 启动在端口: %d\n", socksTap.proxyPort)

	buf := make([]byte, 1024*3)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// 处理每个 UDP 报文
		socksTap.handleUDPData(conn, remoteAddr, buf[:n])
	}
}
