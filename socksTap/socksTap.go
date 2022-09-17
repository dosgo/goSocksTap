package socksTap

import (
	"errors"
	"fmt"
	"goSocksTap/comm"
	"goSocksTap/comm/dot"
	"goSocksTap/comm/netstat"
	"goSocksTap/comm/socks"
	"goSocksTap/winDivert"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dosgo/go-tun2socks/core"
	"github.com/dosgo/go-tun2socks/tun"
	"github.com/dosgo/go-tun2socks/tun2socks"

	"github.com/miekg/dns"
	"github.com/vishalkuo/bimap"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

var dnsCache *comm.DnsCache

func init() {
	dnsCache = &comm.DnsCache{Cache: make(map[string]string, 128)}
}

type SocksTap struct {
	localSocks     string
	udpLimit       sync.Map
	run            bool
	tunDns         *TunDns
	safeDns        *dot.DoT
	socksServerPid int
	autoFilter     bool
	udpProxy       bool
	tunDev         io.ReadWriteCloser
}

type TunDns struct {
	dnsClient      *dns.Client
	dnsClientConn  *dns.Conn
	udpServer      *dns.Server
	tcpServer      *dns.Server
	smartDns       int
	excludeDomains []string
	dnsAddr        string
	dnsAddrV6      string
	dnsPort        string
	ip2Domain      *bimap.BiMap
	singleflight   *singleflight.Group
}

var tunAddr = "10.0.0.2"
var tunGW = "10.0.0.1"
var tunMask = "255.255.0.0"
var fakeUdpNat sync.Map
var ipv6To4 sync.Map

func (fakeDns *SocksTap) Start(localSocks string, excludeDomain string, autoFilter bool, udpProxy bool) {
	fakeDns.localSocks = localSocks
	fakeDns.udpProxy = udpProxy
	if runtime.GOOS == "windows" {
		if excludeDomain == "" {
			fakeDns.autoFilter = true
		} else {
			fakeDns.autoFilter = autoFilter
		}
		fakeDns.socksServerPid, _ = netstat.PortGetPid(localSocks)
	}

	fakeDns.safeDns = &dot.DoT{ServerName: "dns.google", Addr: "8.8.8.8:853", LSocks: localSocks}
	fakeDns.safeDns.Connect()

	//start local dns
	fakeDns.tunDns = &TunDns{smartDns: 1, dnsPort: "653", dnsAddr: "127.0.0.1", dnsAddrV6: "0:0:0:0:0:0:0:1"}
	fakeDns.tunDns.ip2Domain = bimap.NewBiMap()
	fakeDns.tunDns.singleflight = &singleflight.Group{}
	fakeDns.tunDns.excludeDomains = make([]string, 0)
	if excludeDomain != "" {
		fakeDns.tunDns.excludeDomains = append(fakeDns.tunDns.excludeDomains, excludeDomain+".")
	}

	//生成本地udp端口避免过滤的时候变动了
	clientPort, _ := comm.GetFreeUdpPort()
	fakeDns.tunDns._startSmartDns(clientPort)

	//edit DNS
	if runtime.GOOS != "windows" {
		comm.SetNetConf(fakeDns.tunDns.dnsAddr, fakeDns.tunDns.dnsAddrV6)
	}
	fakeDns._startTun(1500)
	if runtime.GOOS == "windows" {
		go winDivert.RedirectDNS(fakeDns.tunDns.dnsAddr, fakeDns.tunDns.dnsPort, clientPort)
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
	tunAddr, tunGW = comm.GetUnusedTunAddr()
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
	var srcAddr = conn.LocalAddr().String()
	var srcAddrs = strings.Split(srcAddr, ":")
	var remoteAddr = ""
	var addrType = 0x01
	defer conn.Close()
	if fakeDns.autoFilter && netstat.IsSocksServerAddr(fakeDns.socksServerPid, srcAddrs[0]) {
		domain := fakeDns.dnsToDomain(srcAddr)
		domains := strings.Split(domain, ":")
		fmt.Printf("IsSocksServerAddr:%d  addr:%s domain:%s\r\n", fakeDns.socksServerPid, srcAddrs[0], domains[0])
		if domain == "" {
			fmt.Printf("dnsToDomain domain:%s srcAddr:%s\r\n", domain, srcAddr)
			return nil
		}
		//add exclude  domain
		fakeDns.tunDns.excludeDomains = append(fakeDns.tunDns.excludeDomains, domains[0])
		ip, _, err := fakeDns.tunDns.localResolve(domains[0], 4)
		if err != nil {
			fmt.Printf("domain:%s  srcAddr:%s localResolve err:%s\r\n", domains[0], srcAddr, err)
			return nil
		}
		socksConn, err := net.DialTimeout("tcp", ip.String()+":"+srcAddrs[1], time.Second*15)
		if err != nil {
			return nil
		}
		defer socksConn.Close()
		comm.TcpPipe(conn, socksConn, time.Minute*5)
	} else {
		remoteAddr = fakeDns.dnsToAddr(srcAddr)
		if remoteAddr == "" {
			fmt.Printf("remoteAddr:%s srcAddr:%s\r\n", remoteAddr, srcAddr)
			return nil
		}
		socksConn, err := net.DialTimeout("tcp", fakeDns.localSocks, time.Second*15)
		if err != nil {
			log.Printf("err:%v", err)
			return nil
		}
		defer socksConn.Close()
		if socks.SocksCmd(socksConn, 1, uint8(addrType), remoteAddr) == nil {
			comm.TcpPipe(conn, socksConn, time.Minute*5)
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
			fmt.Printf("gateWay:%s %v\r\n", gateWay, err)
			if err == nil {
				defer ep.Close()
				dstAddr, _ := net.ResolveUDPAddr("udp", remoteAddr)
				fmt.Printf("udp-remoteAddr:%s\r\n", remoteAddr)
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
	return _domain.(string) + ":" + remoteAddrs[1]
}

func (tunDns *TunDns) _startSmartDns(clientPort string) {
	tunDns.udpServer = &dns.Server{
		Net:          "udp",
		Addr:         ":" + tunDns.dnsPort,
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}
	tunDns.tcpServer = &dns.Server{
		Net:          "tcp",
		Addr:         ":" + tunDns.dnsPort,
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}

	localPort, _ := strconv.Atoi(clientPort)
	netAddr := &net.UDPAddr{Port: localPort}
	_Dialer := &net.Dialer{Timeout: 3 * time.Second, LocalAddr: netAddr}
	tunDns.dnsClient = &dns.Client{
		Net:            "udp",
		UDPSize:        4096,
		Dialer:         _Dialer,
		SingleInflight: true,
		ReadTimeout:    time.Duration(3) * time.Second,
		WriteTimeout:   time.Duration(2) * time.Second,
	}
	tunDns.dnsClientConn, _ = tunDns.dnsClient.Dial(comm.GetUseDns(tunDns.dnsAddr, tunGW, "") + ":53")
	go tunDns.udpServer.ListenAndServe()
	go tunDns.tcpServer.ListenAndServe()
}

func (tunDns *TunDns) Shutdown() {
	if tunDns.tcpServer != nil {
		tunDns.tcpServer.Shutdown()
	}
	if tunDns.udpServer != nil {
		tunDns.udpServer.Shutdown()
	}
}

/*ipv4查询代理*/
func (tunDns *TunDns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Authoritative = false
	domain := r.Question[0].Name
	v, err, _ := tunDns.singleflight.Do(domain+":4", func() (interface{}, error) {
		return tunDns.ipv4Res(domain)
	})
	m.Answer = []dns.RR{v.(*dns.A)}
	// final
	return m, err
}

/*ipv6查询代理*/
func (tunDns *TunDns) doIPv6Query(r *dns.Msg) (*dns.Msg, error) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Authoritative = false
	domain := r.Question[0].Name
	v, err, _ := tunDns.singleflight.Do(domain+":6", func() (interface{}, error) {
		return tunDns.ipv6Res(domain)
	})
	_, isA := v.(*dns.A)
	if isA {
		m.Answer = []dns.RR{v.(*dns.A)}
	}
	_, isAAAA := v.(*dns.AAAA)
	if isAAAA {
		m.Answer = []dns.RR{v.(*dns.AAAA)}
	}
	// final
	return m, err
}

func (tunDns *TunDns) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var msg *dns.Msg
	var err error
	switch r.Question[0].Qtype {
	case dns.TypeA:
		msg, err = tunDns.doIPv4Query(r)
		break
	case dns.TypeAAAA:
		//ipv6
		msg, err = tunDns.doIPv6Query(r)
		break
	default:
		var rtt time.Duration
		msg, rtt, err = tunDns.dnsClient.ExchangeWithConn(r, tunDns.dnsClientConn)
		fmt.Printf("ServeDNS default rtt:%+v err:%+v\r\n", rtt, err)
		break
	}
	if err != nil {
		msg = &dns.Msg{}
		msg.SetRcode(r, dns.RcodeServerFailure)
	}
	w.WriteMsg(msg)
}

/*ipv4智能响应*/
func (tunDns *TunDns) ipv4Res(domain string) (*dns.A, error) {
	var ip = ""
	var _ip net.IP
	var ipTtl uint32 = 60
	var dnsErr = false
	var backErr error = nil
	ipLog, ok := tunDns.ip2Domain.GetInverse(domain)
	if ok && !comm.ArrMatch(domain, tunDns.excludeDomains) && strings.HasPrefix(ipLog.(string), tunAddr[0:4]) {
		ip = ipLog.(string)
		ipTtl = 1
	} else {
		if _ip == nil && len(domain) > 0 {
			//为空的话智能dns的话先解析一遍
			var backIp net.IP
			backIp, _, err := tunDns.localResolve(domain, 4)
			if err == nil {
				_ip = backIp
			} else if err.Error() != "Not found addr" {
				oldDns := comm.GetUseDns(tunDns.dnsAddr, tunGW, "")
				fmt.Printf("local dns error:%v oldDns:%s\r\n", err, oldDns)
				//检测网关DNS是否改变
				if strings.Index(tunDns.dnsClientConn.RemoteAddr().String(), oldDns) == -1 {
					tunDns.dnsClientConn.Close()
					dnsClientConn, err := tunDns.dnsClient.Dial(oldDns + ":53")
					if err == nil {
						tunDns.dnsClientConn = dnsClientConn
					}
				}
				//解析错误说明无网络,否则就算不存在也会回复的
				dnsErr = true //标记为错误
			}
			//如果只是找不到地址没有任何错误可能只有ipv6地址,标记为空
			if err != nil && err.Error() == "Not found addr" {
				//backErr = errors.New("only ipv6")
				dnsErr = true
			}
		}

		//不为空判断是不是中国ip
		if comm.ArrMatch(domain, tunDns.excludeDomains) || (_ip != nil && (comm.IsChinaMainlandIP(_ip.String()) || !comm.IsPublicIP(_ip))) {
			//中国Ip直接回复
			if _ip != nil {
				ip = _ip.String()
			}
		} else if !comm.ArrMatch(domain, tunDns.excludeDomains) && !dnsErr {
			//外国随机分配一个代理ip
			ip = allocIpByDomain(domain, tunDns)
			ipTtl = 1
		}
	}
	fmt.Printf("domain:%s ip:%s\r\n", domain, ip)
	return &dns.A{
		Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ipTtl},
		A:   net.ParseIP(ip),
	}, backErr
}

/*ipv6智能判断*/
func (tunDns *TunDns) ipv6Res(domain string) (interface{}, error) {
	ipLog, ok := tunDns.ip2Domain.GetInverse(domain)
	_, ok1 := ipv6To4.Load(domain)
	if ok && ok1 && !comm.ArrMatch(domain, tunDns.excludeDomains) && strings.HasPrefix(ipLog.(string), tunAddr[0:4]) {
		//ipv6返回错误迫使使用ipv4地址
		return nil, errors.New("use ipv4")
	}

	//ipv6
	ipStr, rtt, err := tunDns.localResolve(domain, 6)
	fmt.Printf("ipv6:%s  rtt:%+v err:%+v\r\n", domain, rtt, err)
	if err == nil {
		if ipStr.String() == "" {
			//返回ipv6地址
			return &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
				AAAA: net.ParseIP(""),
			}, nil
		}
		ipv6Addr := net.ParseIP(ipStr.String())
		//私有地址或者环路地址或者Teredo地址说明被污染了...返回ipv4的代理ip
		if ipv6Addr.IsPrivate() || ipv6Addr.IsLoopback() || isTeredo(ipv6Addr) {
			ipv6To4.Store(domain, 1)
			//ipv6返回错误迫使使用ipv4地址
			return nil, errors.New("use ipv4")
		} else {
			//返回ipv6地址
			return &dns.AAAA{
				Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 1},
				AAAA: net.ParseIP(ipStr.String()),
			}, nil
		}
	}
	return nil, err
}

/*ipv6 teredo addr (4to6)*/
func isTeredo(addr net.IP) bool {
	if len(addr) != 16 {
		return false
	}
	return addr[0] == 0x20 && addr[1] == 0x01 && addr[2] == 0x00 && addr[3] == 0x00
}

/*
本地dns解析有缓存
domain 域名有最后一个"."
*/
func (tunDns *TunDns) localResolve(domain string, ipType int) (net.IP, uint32, error) {
	query := &dns.Msg{}
	if ipType == 4 {
		query.SetQuestion(domain, dns.TypeA)
	}
	if ipType == 6 {
		query.SetQuestion(domain, dns.TypeAAAA)
	}
	cache, ttl := dnsCache.ReadDnsCache(domain + ":" + strconv.Itoa(ipType))
	if cache != "" {
		return net.ParseIP(cache), ttl, nil
	}
	m1, rtt, err := tunDns.dnsClient.ExchangeWithConn(query, tunDns.dnsClientConn)
	fmt.Printf("localResolve:%s  ipType:%d  rtt:%+v err:%+v\r\n", domain, ipType, rtt, err)
	if err == nil {
		for _, v := range m1.Answer {
			if ipType == 4 {
				record, isType := v.(*dns.A)
				if isType {
					//有些dns会返回127.0.0.1
					if record.A.String() != "127.0.0.1" {
						dnsCache.WriteDnsCache(domain+":"+strconv.Itoa(ipType), record.Hdr.Ttl, record.A.String())
						return record.A, record.Hdr.Ttl, nil
					}
				}
			}
			if ipType == 6 {
				record, isType := v.(*dns.AAAA)
				if isType {
					dnsCache.WriteDnsCache(domain+":"+strconv.Itoa(ipType), record.Hdr.Ttl, record.AAAA.String())
					return record.AAAA, record.Hdr.Ttl, nil
				}
			}
		}
	} else {
		return nil, 0, err
	}
	return nil, 0, errors.New("Not found addr")
}

/*给域名分配私有地址*/
func allocIpByDomain(domain string, tunDns *TunDns) string {
	var ip = ""
	for i := 0; i <= 2; i++ {
		ip = comm.GetCidrRandIpByNet(tunAddr, tunMask)
		_, ok := tunDns.ip2Domain.Get(ip)
		if !ok && ip != tunAddr {
			tunDns.ip2Domain.Insert(ip, domain)
			break
		} else {
			fmt.Println("ip used up")
			ip = ""
		}
	}
	return ip
}
