package socksTap

import (
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
	"golang.org/x/net/proxy"
)

type SocksTap struct {
	proxyPort      uint16
	localSocks     string
	mode           int //0全局代理 1绕过局域网和中国大陆地址代理
	dialer         proxy.Dialer
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
		go forward.CollectDNSRecords(socksTap.dnsRecords)
	}
	var err error
	socksTap.dialer, err = proxy.SOCKS5("tcp", socksTap.localSocks, nil, getDialer())
	if err != nil {
		log.Printf("SOCKS5 拨号失败: %v", err)
		return
	}
	go socksTap.task()
	// 1. 启动本地代理中转服务器
	go socksTap.startLocalRelay()
	go forward.NetEvent(socksTap.socksServerPid, &excludePorts)
	// 2. 开启 WinDivert 拦截并重定向所有 TCP 流量
	go forward.RedirectAllTCP(socksTap.proxyPort, &excludePorts, &originalPorts)
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
