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
	"github.com/vishvananda/netlink"
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
	if socksTap.localSocks != "" && strings.Index(socksTap.localSocks, "127.0.0.1") != -1 {
		isExclude = isPortOwnedByPID(c.RemoteAddr().(*net.TCPAddr).Port, socksTap.socksServerPid, false)
	}
	if socksTap.localSocks != "" && comm.IsProxyRequiredFast(addrs[0]) && !isExclude {
		domain, ok := socksTap.dnsRecords.Get(addrs[0])
		if ok {
			log.Printf("domain: %s\r\n", domain)
			targetStr = net.JoinHostPort(strings.TrimSuffix(domain, "."), addrs[1])
		} else {
			fmt.Printf("no domain remoteAddr:%s\r\n", targetStr)
		}
		targetConn, err = socksTap.connectProxy(addrs[0], addrs[1], "tcp")
	} else {
		targetConn, err = dialer.Dial("tcp", targetStr)
	}
	if err != nil {
		return
	}
	targetConn = comm.NewTimeoutConn(targetConn, time.Second*120, time.Second*120)
	defer targetConn.Close()
	localConn := comm.NewTimeoutConn(c, time.Second*120, time.Second*120)
	// 双向转发
	go func() {
		io.Copy(targetConn, localConn)
		localConn.Close()
	}()
	io.Copy(localConn, targetConn)
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

func (socksTap *SocksTap) handleUDPData(localConn *net.UDPConn, clientAddr *net.UDPAddr, data []byte) {
	addrInfo := socksTap.udpNat.GetAddrFromVirtualPort(uint16(clientAddr.Port))
	if addrInfo == nil {
		fmt.Printf("no origPort clientAddr.Port:%d\r\n", clientAddr.Port)
		return
	}
	origPort := addrInfo.DstPort
	vPortKey := fmt.Sprintf("udp:%d", clientAddr.Port)
	// 检查这个“客户端”是否已经有对应的“转发隧道”了
	conn, ok := socksTap.udpClients.Load(vPortKey)

	if !ok {
		isExclude := false
		if socksTap.localSocks != "" && strings.Index(socksTap.localSocks, "127.0.0.1") != -1 {
			isExclude = isPortOwnedByPID(int(addrInfo.SrcPort), socksTap.socksServerPid, true)
		}
		var proxyConn net.Conn
		var err error
		remoteAddr := net.JoinHostPort(clientAddr.IP.String(), strconv.Itoa(int(origPort)))
		// 如果没有，就 Dial 一个（类似于 TCP 的 Accept 过程）
		// 这里的 dialer 就是你之前配置的带 SO_MARK 的 socks5.Dialer
		if socksTap.localSocks != "" && comm.IsProxyRequiredFast(clientAddr.IP.String()) && !isExclude {
			udpConn, err := socksTap.connectProxy(clientAddr.IP.String(), strconv.Itoa(int(origPort)), "udp")
			if err != nil {
				fmt.Printf("udp err:%+v\r\n", err)
				return
			}
			proxyConn = udpConn

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
			timeConn := comm.NewTimeoutConn(c, time.Second*120, time.Second*120)
			for {
				rn, err := timeConn.Read(resp)
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
func isPortOwnedByPID(srcPort int, targetPid int, udp bool) bool {
	fdPath := fmt.Sprintf("/proc/%d/fd", targetPid)
	fds, err := os.ReadDir(fdPath)
	//如果进程没了全部直连避免死循环
	if err != nil {
		return true
	}

	targetInodes := make(map[uint32]struct{})
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(fdPath, fd.Name()))
		if err != nil || !strings.HasPrefix(link, "socket:[") {
			continue
		}
		// 提取 socket:[12345] 中的 12345
		inodeStr := link[8 : len(link)-1]
		inode, err := strconv.ParseUint(inodeStr, 10, 32)
		if err == nil {
			targetInodes[uint32(inode)] = struct{}{}
		}
	}

	if len(targetInodes) == 0 {
		return false
	}

	families := []uint8{syscall.AF_INET, syscall.AF_INET6}

	for _, family := range families {
		if udp {
			sockets, err := netlink.SocketDiagUDPInfo(family) // 也可以是
			if err != nil {
				return false
			}
			for _, s := range sockets {
				// 匹配端口
				if s.InetDiagMsg.ID.SourcePort == uint16(srcPort) {
					// 在 Linux 中，Netlink 诊断信息直接包含 Inode
					if _, ok := targetInodes[s.InetDiagMsg.INode]; ok {
						return true
					}
				}
			}
		} else {
			sockets, err := netlink.SocketDiagTCPInfo(family)
			if err != nil {
				return false
			}
			for _, s := range sockets {
				// 匹配端口
				if s.InetDiagMsg.ID.SourcePort == uint16(srcPort) {
					// 在 Linux 中，Netlink 诊断信息直接包含 Inode
					if _, ok := targetInodes[s.InetDiagMsg.INode]; ok {
						return true
					}
				}
			}
		}
	}

	return false
}
