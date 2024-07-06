package socksTap

import (
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/dot"
	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/dosgo/goSocksTap/comm/socks"
	"github.com/dosgo/goSocksTap/winDivert"

	"github.com/dosgo/go-tun2socks/core"
	"github.com/dosgo/go-tun2socks/tun"
	"github.com/dosgo/go-tun2socks/tun2socks"

	"github.com/vishalkuo/bimap"
	"golang.org/x/time/rate"
)

type SocksTap struct {
	localSocks     string
	udpLimit       sync.Map
	run            bool
	tunDns         *TunDns
	socksServerPid int
	safeDns        *dot.DoT
	udpProxy       bool
	tunDev         io.ReadWriteCloser
}

var tunAddr = "10.0.0.2"
var tunGW = "10.0.0.1"
var tunMask = "255.255.0.0"
var fakeUdpNat sync.Map
var ipv6To4 sync.Map

func (fakeDns *SocksTap) Start(localSocks string, excludeDomain string, udpProxy bool) {
	fakeDns.localSocks = localSocks
	fakeDns.udpProxy = udpProxy
	tunAddr, tunGW = comm.GetUnusedTunAddr()
	fakeDns.safeDns = dot.NewDot("dns.google", "8.8.8.8:853", localSocks)
	//start local dns
	fakeDns.tunDns = &TunDns{dnsPort: "53", dnsAddr: tunAddr}
	//fakeDns.tunDns = &TunDnsV1{dnsPort: "53", dnsAddr: tunAddr}
	fakeDns.tunDns.ip2Domain = bimap.NewBiMap[string, string]()
	fakeDns.tunDns.excludeDomains = make(map[string]uint8)
	if runtime.GOOS == "windows" {
		fakeDns.socksServerPid, _ = netstat.PortGetPid(localSocks)
		fakeDns.tunDns.dnsPort = "653" //为了避免死循环windows使用653端口
	}
	fakeDns._startTun(1500)
	if excludeDomain != "" {
		excludeDomainList := strings.Split(excludeDomain, ";")
		for i := 0; i < len(excludeDomainList); i++ {
			fakeDns.tunDns.excludeDomains[excludeDomainList[i]+"."] = 1
		}
	}

	fakeDns.tunDns.StartSmartDns()

	//edit DNS
	if runtime.GOOS != "windows" {
		comm.SetNetConf(fakeDns.tunDns.dnsAddr)
	}
	if runtime.GOOS == "windows" {
		fakeDns.tunDns.sendMinPort = 600
		fakeDns.tunDns.sendMaxPort = 700
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
		fakeDns.udpLimit.Range(func(k, v interface{}) bool {
			_v := v.(*comm.UdpLimit)
			if _v.Expired < time.Now().Unix() {
				fakeDns.udpLimit.Delete(k)
			}
			return true
		})
		if runtime.GOOS == "windows" {
			pid, err := netstat.PortGetPid(fakeDns.localSocks)
			if err == nil && pid > 0 {
				fakeDns.socksServerPid = pid
			}
		}
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
		fakeDns.tunDns.excludeDomains[domain] = 1 //标记为跳过代理域名
		localIp, _, err := fakeDns.tunDns.localResolve(domain, 4)
		if err != nil {
			log.Printf("localIp:%s srcAddr:%s domain:%s\r\n", localIp.String(), srcAddr, domain[0:len(domain)-1])
			return nil
		}
		socksConn, err := net.DialTimeout("tcp", localIp.String()+":"+remoteAddrs[1], time.Second*15)
		if err != nil {
			log.Printf("err:%v", err)
			return nil
		}
		defer socksConn.Close()
		comm.TcpPipe(conn, socksConn, time.Second*70)
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
			log.Printf("err:%v", err)
			return nil
		}
		defer socksConn.Close()
		if socks.SocksCmd(socksConn, 1, uint8(addrType), remoteAddr, true) == nil {
			comm.TcpPipe(conn, socksConn, time.Second*70)
		}
	}
	return nil
}

func (fakeDns *SocksTap) udpForwarder(conn core.CommUDPConn, ep core.CommEndpoint) error {
	var srcAddr = conn.LocalAddr().String()
	var remoteAddr = ""
	remoteAddr = fakeDns.dnsToAddr(srcAddr)
	if remoteAddr == "" {
		conn.Close()
		return nil
	}
	if fakeDns.udpProxy {
		socksConn, err := net.DialTimeout("tcp", fakeDns.localSocks, time.Second*15)
		if err == nil {
			defer socksConn.Close()
			gateWay, err := socks.GetUdpGate(socksConn, remoteAddr)
			log.Printf("gateWay:%s %v\r\n", gateWay, err)
			if err == nil {
				defer ep.Close()
				dstAddr, _ := net.ResolveUDPAddr("udp", remoteAddr)
				log.Printf("udp-remoteAddr:%s\r\n", remoteAddr)
				return socks.SocksUdpGate(conn, gateWay, dstAddr)
			}
		}
	}
	fakeDns.UdpDirect(remoteAddr, conn, ep)
	return nil
}

/*直连*/
func (fakeDns *SocksTap) UdpDirect(remoteAddr string, conn core.CommUDPConn, ep core.CommEndpoint) {
	//tuntype 直连
	var limit *comm.UdpLimit
	_limit, ok := fakeDns.udpLimit.Load(remoteAddr)
	if !ok {
		limit = &comm.UdpLimit{Limit: rate.NewLimiter(rate.Every(1*time.Second), 50), Expired: time.Now().Unix() + 5}
	} else {
		limit = _limit.(*comm.UdpLimit)
	}
	//限流
	if limit.Limit.Allow() {
		limit.Expired = time.Now().Unix() + 5
		//本地直连交换
		comm.TunNatSawp(&fakeUdpNat, conn, ep, remoteAddr, 65*time.Second)
		fakeDns.udpLimit.Store(remoteAddr, limit)
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
