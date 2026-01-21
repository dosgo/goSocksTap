package socksTap

import (
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
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
		socksTap.socksServerPid, _ = netstat.PortGetPid(socksTap.localSocks)
		socksTap.dnsRecords = expirable.NewLRU[string, string](10000, nil, time.Minute*5)
		go winDivert.CollectDNSRecords(socksTap.dnsRecords)
	}
	var err error
	socksTap.dialer, err = proxy.SOCKS5("tcp", socksTap.localSocks, nil, proxy.Direct)
	if err != nil {
		log.Printf("SOCKS5 拨号失败: %v", err)
		return
	}
	go socksTap.task()
	// 1. 启动本地代理中转服务器
	go socksTap.startLocalRelay()
	go winDivert.NetEvent(socksTap.socksServerPid, &excludePorts)
	// 2. 开启 WinDivert 拦截并重定向所有 TCP 流量
	go winDivert.RedirectAllTCP(socksTap.proxyPort, &excludePorts, &originalPorts)
}
func (socksTap *SocksTap) Close() {
	socksTap.run = false
	winDivert.CloseWinDivert()
}

func (socksTap *SocksTap) task() {
	for socksTap.run {
		if runtime.GOOS == "windows" && socksTap.localSocks != "" {
			pid, err := netstat.PortGetPid(socksTap.localSocks)
			if err == nil && pid > 0 && pid != socksTap.socksServerPid {
				socksTap.socksServerPid = pid
				winDivert.CloseNetEvent()
				time.Sleep(time.Second * 1)
				go winDivert.NetEvent(socksTap.socksServerPid, &excludePorts)
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
