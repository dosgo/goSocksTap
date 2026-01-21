//go:build windows
// +build windows

package socksTap

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

func (socksTap *SocksTap) handleConnection(conn net.Conn) {
	defer conn.Close()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		// 核心点：由于使用了反射，conn.RemoteAddr() 实际上是原始的目标服务器地址
		//	log.Printf("[拦截流量] 目标: %s\n", tcpAddr.String())
		key := fmt.Sprintf("%d", tcpAddr.Port)
		if origPort, ok := originalPorts.Load(key); ok {
			var targetConn net.Conn
			var err error
			if socksTap.localSocks != "" && socksTap.dialer != nil {
				domain, ok := socksTap.dnsRecords.Get(tcpAddr.IP.String())
				remoteAddr := net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16))))
				if ok {
					//log.Printf("domain: %s\r\n", domain)
					remoteAddr = net.JoinHostPort(strings.TrimSuffix(domain, "."), strconv.Itoa(int(origPort.(uint16))))
				} else {
					fmt.Printf("no domain remoteAddr:%s\r\n", remoteAddr)
				}
				targetConn, err = socksTap.dialer.Dial("tcp", remoteAddr)
			} else {
				targetConn, err = net.DialTimeout("tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16)))), 5*time.Second)
			}
			if err != nil || targetConn == nil {
				log.Printf("connect err: %v", err)
				return
			}
			defer excludePorts.Delete(fmt.Sprintf("%d", targetConn.LocalAddr().(*net.TCPAddr).Port))
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
