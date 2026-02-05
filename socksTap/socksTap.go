package socksTap

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/dosgo/goSocksTap/comm/udpProxy"
	"github.com/dosgo/goSocksTap/forward"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/wzshiming/socks5"
)

var randPorts = []uint16{
	1111,
	1112,
	1113,
	1114,
	1115,
}

type SocksTap struct {
	proxyPort   uint16
	localSocks  string
	mode        int //0全局代理 1绕过局域网和中国大陆地址代理
	dnsRecords  *expirable.LRU[string, string]
	run         bool
	useUdpRelay bool
	udpClients  *sync.Map
	//excludePorts    *sync.Map
	udpExcludePorts *comm.PortBitmap
	tcpExcludePorts *comm.PortBitmap
	originalPorts   *sync.Map
	udpNat          *udpProxy.UdpNat
	socksServerPid  int
}

func NewSocksTap(localSocks string, mode int, useUdpRelay bool) *SocksTap {
	comm.SetProxyMode(mode)
	info := &SocksTap{
		localSocks:  localSocks,
		mode:        mode,
		useUdpRelay: useUdpRelay,
	}
	info.udpClients = &sync.Map{}
	info.tcpExcludePorts = &comm.PortBitmap{}
	info.udpExcludePorts = &comm.PortBitmap{}
	info.originalPorts = &sync.Map{}
	return info
}

func (socksTap *SocksTap) Start() {
	socksTap.run = true
	//随机端口
	socksTap.proxyPort = randPorts[rand.Intn(len(randPorts))]
	// 1. 启动本地代理中转服务器
	go socksTap.startLocalRelay()
	go socksTap.task()
	time.Sleep(time.Millisecond * 20)
	if socksTap.localSocks != "" {
		socksTap.dnsRecords = expirable.NewLRU[string, string](10000, nil, time.Minute*5)
		go forward.CollectDNSRecords(socksTap.dnsRecords)
	}

	go forward.RedirectAllTCP(socksTap.proxyPort, socksTap.tcpExcludePorts, socksTap.originalPorts)
	if socksTap.useUdpRelay {
		socksTap.udpNat = udpProxy.NewUdpNat()
		go socksTap.startLocalUDPRelay()
		// 开启 WinDivert UDP 拦截
		go forward.RedirectAllUDP(socksTap.proxyPort, socksTap.udpExcludePorts, socksTap.originalPorts, socksTap.udpNat)
	}
}
func (socksTap *SocksTap) Close() {
	socksTap.run = false
	forward.Stop()
}

func (socksTap *SocksTap) task() {
	for socksTap.run {
		if socksTap.localSocks != "" {
			pid, err := netstat.PortGetPid(socksTap.localSocks)
			if err == nil && pid > 0 && pid != socksTap.socksServerPid {
				socksTap.socksServerPid = pid
				if runtime.GOOS == "windows" {
					forward.CheckUpdate(socksTap.socksServerPid, socksTap.tcpExcludePorts, socksTap.udpExcludePorts)
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
	log.Printf("startLocalRelay:%d\r\n", socksTap.proxyPort)
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

type socksConnWrapper struct {
	net.Conn           // 逻辑上的 UDP Conn
	proxyConn net.Conn // 底层的 TCP 控制连接
}

func (w *socksConnWrapper) Close() error {
	// 先关掉底层的 TCP，这会强制触发服务端释放 UDP 关联
	if w.proxyConn != nil {
		w.proxyConn.Close()
	}
	// 再关掉逻辑连接
	return w.Conn.Close()
}
func (socksTap *SocksTap) connectProxy(ip string, origPort string, network string) (*socksConnWrapper, error) {
	socksClient, err := socks5.NewDialer(socksTap.localSocks)
	if err != nil {
		log.Printf("SOCKS5 拨号失败: %v", err)
		return nil, err
	}
	var underlyingConn net.Conn
	socksClient.ProxyDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		//return getDialer().DialContext(ctx, network, address)
		c, err := getDialer(socksTap).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		underlyingConn = c
		return c, nil
	}

	remoteAddr := net.JoinHostPort(ip, origPort)
	domain, ok := socksTap.dnsRecords.Get(ip)
	if ok {
		remoteAddr = net.JoinHostPort(strings.TrimSuffix(domain, "."), origPort)
		log.Printf("proxy %s domain remoteAddr:%s\r\n", network, remoteAddr)
	} else {
		log.Printf("proxy %s no domain remoteAddr:%s\r\n", network, remoteAddr)
	}
	targetConn, err := socksClient.DialContext(context.Background(), network, remoteAddr)
	if err != nil {
		if underlyingConn != nil {
			underlyingConn.Close()
		}
		return nil, err
	}
	return &socksConnWrapper{
		Conn:      targetConn,
		proxyConn: underlyingConn,
	}, nil
}
