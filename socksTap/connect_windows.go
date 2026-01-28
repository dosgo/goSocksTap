//go:build windows
// +build windows

package socksTap

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cakturk/go-netstat/netstat"
)

func (socksTap *SocksTap) handleConnection(conn net.Conn) {
	defer conn.Close()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		// 核心点：由于使用了反射，conn.RemoteAddr() 实际上是原始的目标服务器地址
		//	log.Printf("[拦截流量] 目标: %s\n", tcpAddr.String())
		key := fmt.Sprintf("%d", tcpAddr.Port)
		if origPort, ok := socksTap.originalPorts.Load(key); ok {
			var targetConn net.Conn
			var err error
			remoteAddr := net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16))))
			if socksTap.localSocks != "" && socksTap.socksClient != nil {
				domain, ok := socksTap.dnsRecords.Get(tcpAddr.IP.String())
				if ok {
					//log.Printf("domain: %s\r\n", domain)
					remoteAddr = net.JoinHostPort(strings.TrimSuffix(domain, "."), strconv.Itoa(int(origPort.(uint16))))
				} else {
					fmt.Printf("no domain remoteAddr:%s\r\n", remoteAddr)
				}
				targetConn, err = socksTap.socksClient.Dial("tcp", remoteAddr)
			} else {
				targetConn, err = net.DialTimeout("tcp", remoteAddr, 5*time.Second)
			}
			if err != nil || targetConn == nil {
				log.Printf("tcp connect err: %v", err)
				return
			}
			defer socksTap.excludePorts.Delete(fmt.Sprintf("tcp:%d", targetConn.LocalAddr().(*net.TCPAddr).Port))
			//log.Printf("src port:%d\r\n", targetConn.LocalAddr().(*net.TCPAddr).Port)
			defer targetConn.Close()
			// 双向数据拷贝 (你可以在这里打印/记录 payload 内容)
			go io.Copy(targetConn, conn)
			io.Copy(conn, targetConn)
		} else {
			log.Printf("err addr:%s\r\n", tcpAddr.String())
		}
	}
}
func getDialer() *net.Dialer {
	return &net.Dialer{}
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
		remoteAddr := net.JoinHostPort(clientAddr.IP.String(), strconv.Itoa(int(origPort)))
		var proxyConn net.Conn
		var lPort uint16 = 0
		// 如果没有，就 Dial 一个（类似于 TCP 的 Accept 过程）
		// 这里的 dialer 就是你之前配置的带 SO_MARK 的 socks5.Dialer
		if socksTap.localSocks != "" && socksTap.socksClient != nil && !isPortOwnedByPID(int(addrInfo.SrcPort), socksTap.socksServerPid) {
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
			remoteUdpAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
			if err != nil {
				return
			}
			proxyConn, err = net.DialUDP("udp", nil, remoteUdpAddr)
			lAddr := proxyConn.LocalAddr().(*net.UDPAddr)
			socksTap.excludePorts.Store(fmt.Sprintf("udp:%d", lAddr.Port), time.Now().Unix()) // 告诉 WinDivert：这个端口发的包别拦
			lPort = uint16(lAddr.Port)
		}
		// 启动一个协程专门负责这个“连接”的回包（像 TCP 处理一样）
		go func(c net.Conn, addr *net.UDPAddr, lport uint16) {
			defer c.Close()
			defer socksTap.udpClients.Delete(vPortKey)
			if lport != 0 {
				defer socksTap.excludePorts.Delete(fmt.Sprintf("udp:%d", lport)) // 告诉 WinDivert：这个端口发的包别拦
			}
			resp := make([]byte, 2048)
			for {
				c.SetReadDeadline(time.Now().Add(time.Second * 60))
				rn, err := c.Read(resp)
				if err != nil {
					return
				} // 这里不需要 ReadFrom，因为它已经“连”上了
				localConn.WriteToUDP(resp[:rn], addr) // 发回给客户端
			}
		}(proxyConn, clientAddr, lPort)
		socksTap.udpClients.Store(vPortKey, proxyConn)
		conn = proxyConn
	}
	// 像 TCP 写入一样简单
	conn.(net.Conn).Write(data)
}
func isPortOwnedByPID(srcPort int, targetPid int) bool {
	// 获取所有 UDP 状态
	tbl, err := netstat.GetUDPTableOwnerPID(true)
	if err != nil {
		return false
	}
	var _slefPid = os.Getpid()
	s := tbl.Rows()
	for i := range s {
		if s[i].LocalSock().Port == uint16(srcPort) && (int(s[i].WinPid) == targetPid || int(s[i].WinPid) == _slefPid) {
			return true
		}
	}
	return false
}
