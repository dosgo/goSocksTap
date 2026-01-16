package socksTap

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/dosgo/goSocksTap/winDivert"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/net/proxy"
)

type SocksTap struct {
	proxyPort  uint16
	localSocks string
	bypass     bool
	dialer     proxy.Dialer
	dnsRecords *expirable.LRU[string, string]
}

// 配置参数
var (
	excludePorts  = sync.Map{}
	originalPorts = sync.Map{}
)

func NewSocksTap(proxyPort uint16, localSocks string, bypass bool) *SocksTap {
	return &SocksTap{
		proxyPort:  proxyPort,
		localSocks: localSocks,
		bypass:     bypass,
	}
}

func (socksTap *SocksTap) Start() {
	var socksServerPid = 0
	if socksTap.localSocks != "" {
		socksServerPid, _ = netstat.PortGetPid(socksTap.localSocks)
		socksTap.dnsRecords = expirable.NewLRU[string, string](10000, nil, time.Minute*5)
		go winDivert.CollectDNSRecords(socksTap.dnsRecords)
	}
	var err error
	socksTap.dialer, err = proxy.SOCKS5("tcp", socksTap.localSocks, nil, proxy.Direct)
	if err != nil {
		log.Printf("SOCKS5 拨号失败: %v", err)
		return
	}
	// 1. 启动本地代理中转服务器
	go socksTap.startLocalRelay()
	//之前连接的端口也要绑定
	if socksServerPid > 0 {
		bindPorts, _ := netstat.GetTcpBindList(socksServerPid, true)
		for _, v := range bindPorts {
			excludePorts.Store(fmt.Sprintf("%d", v), 1)
		}
	}
	go winDivert.NetEvent(socksServerPid, &excludePorts)
	// 2. 开启 WinDivert 拦截并重定向所有 TCP 流量
	go winDivert.RedirectAllTCP(socksTap.proxyPort, &excludePorts, &originalPorts)
}
func (socksTap *SocksTap) Close() {
	winDivert.CloseWinDivert()
}

// 代理中转逻辑
func (socksTap *SocksTap) startLocalRelay() {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", socksTap.proxyPort))
	if err != nil {
		log.Fatalf("代理监听失败: %v", err)
	}
	fmt.Printf("startLocalRelay\r\n")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go socksTap.handleConnection(conn)
	}
}

func (socksTap *SocksTap) handleConnection(conn net.Conn) {
	defer conn.Close()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		// 核心点：由于使用了反射，conn.RemoteAddr() 实际上是原始的目标服务器地址
		//	fmt.Printf("[拦截流量] 目标: %s\n", tcpAddr.String())
		key := fmt.Sprintf("%d", tcpAddr.Port)
		if origPort, ok := originalPorts.Load(key); ok {
			/*
				dialer := getDialer()
				if dialer == nil {
					return
				}
			*/
			var targetConn net.Conn
			var err error
			if socksTap.localSocks != "" && socksTap.dialer != nil && !comm.IsChinaMainlandIP(tcpAddr.IP.String()) {
				domain, ok := socksTap.dnsRecords.Get(tcpAddr.IP.String())
				remoteAddr := net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16))))
				if ok {
					fmt.Printf("domain: %s\r\n", domain)

					remoteAddr = net.JoinHostPort(strings.TrimSuffix(domain, "."), strconv.Itoa(int(origPort.(uint16))))

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
			//fmt.Printf("src port:%d\r\n", targetConn.LocalAddr().(*net.TCPAddr).Port)
			defer targetConn.Close()
			// 双向数据拷贝 (你可以在这里打印/记录 payload 内容)
			go io.Copy(targetConn, conn)
			io.Copy(conn, targetConn)
		} else {
			fmt.Printf("err addr:%s\r\n", tcpAddr.String())
		}
	}
}

func getDialer() *net.Dialer {
	randomPort, err := GetRandomPort()
	if err != nil {
		fmt.Printf("获取随机端口失败: %v\n", err)
		return nil
	}
	excludePorts.Store(fmt.Sprintf("%d", randomPort), 1)
	// 使用 Dialer 绑定到这个随机端口
	return &net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			Port: randomPort, // 使用随机端口
		},
	}
}
func GetRandomPort() (int, error) {
	// 监听任意地址的0端口，系统会分配随机端口
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port, nil
}
