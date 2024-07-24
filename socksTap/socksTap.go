package socksTap

import (
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/dot"
	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/dosgo/goSocksTap/comm/socks"
	"github.com/dosgo/goSocksTap/winDivert"

	"github.com/dosgo/go-tun2socks/core"
	"github.com/dosgo/go-tun2socks/tun"
	"github.com/dosgo/go-tun2socks/tun2socks"

	"github.com/txthinking/socks5"
	"github.com/vishalkuo/bimap"
)

type SocksTap struct {
	localSocks     string
	run            bool
	tunDns         *TunDnsV1
	socksServerPid int
	safeDns        *dot.DoT
	udpProxy       bool
	tunDev         io.ReadWriteCloser
	udpProxyServer *UdpProxy
}

var tunAddr = "10.0.0.2"
var tunGW = "10.0.0.1"
var tunMask = "255.255.0.0"

func (fakeDns *SocksTap) Start(localSocks string, excludeDomain string, udpProxy bool) {
	fakeDns.localSocks = localSocks
	fakeDns.udpProxy = udpProxy
	tunAddr, tunGW = comm.GetUnusedTunAddr()
	fakeDns.safeDns = dot.NewDot("dns.google", "8.8.8.8:853", localSocks)
	//start local dns
	//fakeDns.tunDns = &TunDns{dnsPort: "53", dnsAddr: tunAddr}
	fakeDns.tunDns = NewTunDns(tunAddr, "53")
	fakeDns.tunDns.sendMinPort = 600
	fakeDns.tunDns.sendMaxPort = 700

	fakeDns.tunDns.ip2Domain = bimap.NewBiMap[string, string]()
	if runtime.GOOS == "windows" {
		fakeDns.socksServerPid, _ = netstat.PortGetPid(localSocks)
		fakeDns.tunDns.dnsPort = "653" //为了避免死循环windows使用653端口
	}
	fakeDns._startTun(1500)
	if excludeDomain != "" {
		excludeDomainList := strings.Split(excludeDomain, ";")
		for i := 0; i < len(excludeDomainList); i++ {
			fakeDns.tunDns.excludeDomains.Store(excludeDomainList[i]+".", 1)
		}
	}

	fakeDns.tunDns.StartSmartDns()

	fakeDns.udpProxyServer = NewUdpProxy(":9999")
	if !fakeDns.udpProxy {
		go fakeDns.udpProxyServer.Start()
	}
	//edit DNS
	if runtime.GOOS != "windows" {
		comm.SetNetConf(fakeDns.tunDns.dnsAddr)
	}
	if runtime.GOOS == "windows" {
		go winDivert.RedirectDNSV2(fakeDns.tunDns.dnsAddr, fakeDns.tunDns.dnsPort, fakeDns.tunDns.sendMinPort, fakeDns.tunDns.sendMaxPort)
		//go winDivert.NetEventv1(strconv.Itoa(fakeDns.tunDns.socksServerPid), true)
		//go winDivert.RedirectDNSV1(fakeDns.tunDns.dnsAddr, fakeDns.tunDns.dnsPort)
	}
	//udp limit auto remove
	fakeDns.run = true
	go fakeDns.task()
}

func (fakeDns *SocksTap) Shutdown() {
	if fakeDns.tunDev != nil {
		fakeDns.tunDev.Close()
	}
	if fakeDns.tunDns != nil {
		comm.ResetNetConf(fakeDns.tunDns.dnsAddr)
		fakeDns.tunDns.Shutdown()
	}
	fakeDns.run = false
	winDivert.CloseWinDivert()
}

func (fakeDns *SocksTap) _startTun(mtu int) error {
	var err error
	fakeDns.tunDev, err = tun.RegTunDev("goSocksTap", tunAddr, tunMask, tunGW, "")
	if err != nil {
		return err
	}
	go func() {
		time.Sleep(time.Second * 1)
		comm.AddRoute(tunAddr, tunGW, tunMask)
	}()
	go tun2socks.ForwardTransportFromIo(fakeDns.tunDev, mtu, fakeDns.tcpForwarder, fakeDns.udpForwarder)
	return nil
}
func (fakeDns *SocksTap) task() {
	for fakeDns.run {
		if runtime.GOOS == "windows" {
			pid, err := netstat.PortGetPid(fakeDns.localSocks)
			if err == nil && pid > 0 {
				fakeDns.socksServerPid = pid
			}
		}
		fakeDns.safeDns.AutoFree()
		time.Sleep(time.Second * 30)
	}
}

func (fakeDns *SocksTap) tcpForwarder(conn core.CommTCPConn) error {
	defer conn.Close()
	var srcAddr = conn.LocalAddr().String()
	//不走代理
	if netstat.IsSocksServerAddr(fakeDns.socksServerPid, conn.RemoteAddr().String()) {

		remoteAddr := fakeDns.dnsToDomain(srcAddr)
		if remoteAddr == "" {
			return nil
		}
		remoteAddrs := strings.Split(remoteAddr, ":")
		domain := remoteAddrs[0]
		fakeDns.tunDns.excludeDomains.Store(domain, 1) //标记为跳过代理域名
		fmt.Printf("add excludeDomains domain:%s\r\n", domain)
		localIp, _, err := fakeDns.tunDns.localResolve(domain, 4)
		if err != nil {
			log.Printf("localIp:%s srcAddr:%s domain:%s\r\n", localIp.String(), srcAddr, domain[0:len(domain)-1])
			return nil
		}
		socksConn, err := net.DialTimeout("tcp", localIp.String()+":"+remoteAddrs[1], time.Second*15)
		if err != nil {
			log.Printf("tcpForwarder err:%v", err)
			return nil
		}
		defer socksConn.Close()
		comm.ConnPipe(conn, socksConn, time.Second*70)
	} else {
		//走代理
		var remoteAddr = ""
		var addrType = 0x01
		remoteAddr = fakeDns.dnsToAddr(srcAddr)
		if remoteAddr == "" {
			log.Printf("remoteAddr:%s srcAddr:%s\r\n", remoteAddr, srcAddr)
			return nil
		}
		socksConn, err := net.DialTimeout("tcp", fakeDns.localSocks, time.Second*15)
		if err != nil {
			log.Printf("tcpForwarder err2:%v", err)
			return nil
		}
		defer socksConn.Close()
		if socks.SocksCmd(socksConn, 1, uint8(addrType), remoteAddr, true) == nil {
			comm.ConnPipe(conn, socksConn, time.Second*70)
		}
	}
	return nil
}

func (fakeDns *SocksTap) udpForwarder(conn core.CommUDPConn, ep core.CommEndpoint) error {
	var srcAddr = conn.LocalAddr().String()
	var remoteAddr = ""
	defer conn.Close()
	remoteAddr = fakeDns.dnsToAddr(srcAddr)
	if remoteAddr == "" {
		return nil
	}
	if fakeDns.udpProxy {
		fakeDns.UdpSocks5(fakeDns.localSocks, remoteAddr, conn)
	} else {
		fakeDns.UdpDirectv1(remoteAddr, conn)
	}
	return nil
}

/*udp UdpSocks5*/
func (fakeDns *SocksTap) UdpSocks5(localSocks string, remoteAddr string, localConn core.CommUDPConn) {

	client, _ := socks5.NewClient(localSocks, "", "", 20, 60)
	udpConn, err := client.Dial("udp", remoteAddr)
	if err == nil {
		defer udpConn.Close()
	}

	buf := make([]byte, 2048)
	go func() {
		buf1 := make([]byte, 2048)
		var readLen = 0
		for {
			udpConn.SetReadDeadline(time.Now().Add(time.Second * 65))
			readLen, err = udpConn.Read(buf1)
			if err != nil {
				break
			}
			localConn.Write(buf1[:readLen])
		}
	}()

	for {
		localConn.SetReadDeadline(time.Now().Add(time.Second * 65))
		udpSize, err := localConn.Read(buf)
		if err == nil {
			udpConn.Write(buf[:udpSize])
		} else {
			break
		}
	}
}

/*直连*/
func (fakeDns *SocksTap) UdpDirectv1(remoteAddr string, conn core.CommUDPConn) {
	buf := make([]byte, 2048)
	defer fakeDns.udpProxyServer.RemoveAddr(remoteAddr)
	for {
		conn.SetReadDeadline(time.Now().Add(time.Second * 65))
		udpSize, err := conn.Read(buf)
		if err == nil {
			fakeDns.udpProxyServer.SendRemote(remoteAddr, buf[:udpSize], conn)
		} else {
			break
		}
	}
}

/*dns addr swap*/
func (fakeDns *SocksTap) dnsToAddr(remoteAddr string) string {
	remoteAddr = fakeDns.dnsToDomain(remoteAddr)
	if remoteAddr == "" {
		return ""
	}
	remoteAddrs := strings.Split(remoteAddr, ":")
	domain := remoteAddrs[0]
	ip, err := fakeDns.safeDns.Resolve(domain[0:len(domain)-1], 4)
	if err != nil {
		return ""
	}
	return ip + ":" + remoteAddrs[1]
}

/*dns addr swap*/
func (fakeDns *SocksTap) dnsToDomain(remoteAddr string) string {
	if fakeDns.tunDns == nil {
		return ""
	}
	remoteAddrs := strings.Split(remoteAddr, ":")
	_domain, ok := fakeDns.tunDns.ip2Domain.Get(remoteAddrs[0])
	if !ok {
		return ""
	}
	return _domain + ":" + remoteAddrs[1]
}

/*ipv6 teredo addr (4to6)*/
func isTeredo(addr net.IP) bool {
	if len(addr) != 16 {
		return false
	}
	return addr[0] == 0x20 && addr[1] == 0x01 && addr[2] == 0x00 && addr[3] == 0x00
}
