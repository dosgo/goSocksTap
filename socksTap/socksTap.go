package socksTap

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/dosgo/goSocksTap/forward"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/wzshiming/socks5"
)

type SocksTap struct {
	proxyPort      uint16
	localSocks     string
	mode           int //0全局代理 1绕过局域网和中国大陆地址代理
	socksClient    *socks5.Dialer
	dnsRecords     *expirable.LRU[string, string]
	run            bool
	socksServerPid int
}

// 配置参数
var (
	excludePorts  = sync.Map{}
	originalPorts = sync.Map{}
)

func NewSocksTap(proxyPort uint16, localSocks string, mode int) *SocksTap {
	comm.SetProxyMode(mode)
	return &SocksTap{
		proxyPort:  proxyPort,
		localSocks: localSocks,
		mode:       mode,
	}
}

func (socksTap *SocksTap) Start() {
	socksTap.run = true

	if socksTap.localSocks != "" {
		var err error

		socksTap.socksServerPid, err = netstat.PortGetPid(socksTap.localSocks)
		fmt.Printf("socksTap.socksServerPid:%d err:%v\r\n", socksTap.socksServerPid, err)
		socksTap.dnsRecords = expirable.NewLRU[string, string](10000, nil, time.Minute*5)
		socksTap.socksClient, err = socks5.NewDialer(socksTap.localSocks)
		if err != nil {
			log.Printf("SOCKS5 拨号失败: %v", err)
			return
		}
		socksTap.socksClient.ProxyDial = func(ctx context.Context, network, address string) (net.Conn, error) {
			return getDialer().DialContext(ctx, network, address)
		}
		go forward.CollectDNSRecords(socksTap.dnsRecords)
	}

	go socksTap.task()
	// 1. 启动本地代理中转服务器
	go socksTap.startLocalRelay()
	go forward.NetEvent(socksTap.socksServerPid, &excludePorts)
	// 2. 开启 WinDivert 拦截并重定向所有 TCP 流量
	go forward.RedirectAllTCP(socksTap.proxyPort, &excludePorts, &originalPorts)

	go socksTap.startLocalUDPRelay()

	// 开启 WinDivert UDP 拦截
	go forward.RedirectAllUDP(socksTap.proxyPort, &excludePorts, &originalPorts)
}
func (socksTap *SocksTap) Close() {
	socksTap.run = false
	forward.CloseWinDivert()
}

func (socksTap *SocksTap) task() {
	for socksTap.run {
		if socksTap.localSocks != "" {
			pid, err := netstat.PortGetPid(socksTap.localSocks)
			if err == nil && pid > 0 && pid != socksTap.socksServerPid {
				socksTap.socksServerPid = pid
				if runtime.GOOS == "windows" {
					forward.CloseNetEvent()
					time.Sleep(time.Second * 1)
					go forward.NetEvent(socksTap.socksServerPid, &excludePorts)
				}
			}
		}
		time.Sleep(time.Second * 30)
	}
}

// 代理中转逻辑
func (socksTap *SocksTap) startLocalRelay() {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", socksTap.proxyPort))
	if err != nil {
		log.Fatalf("代理监听失败: %v", err)
	}
	log.Printf("startLocalRelay\r\n")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go socksTap.handleConnection(conn)
	}
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
