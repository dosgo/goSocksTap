package socksTap

import (
	"errors"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/miekg/dns"
	"github.com/vishalkuo/bimap"
)

var dnsCache *comm.DnsCache

func init() {
	dnsCache = &comm.DnsCache{Cache: make(map[string]comm.IpInfo, 128)}
}

type TunDns struct {
	dnsClient *dns.Client
	srcDns    string
	udpServer *dns.Server
	tcpServer *dns.Server
	run       bool
	//excludeDomains      map[string]uint8
	excludeDomains sync.Map
	dnsAddr        string
	dnsPort        string
	ip2Domain      *bimap.BiMap[string, string]
	sendMinPort    int
	sendMaxPort    int
}

func (tunDns *TunDns) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	if runtime.GOOS != "windows" {
		return tunDns.dnsClient.Exchange(m, tunDns.srcDns)
	}
	_dialer := comm.GetPortDialer(tunDns.sendMinPort, tunDns.sendMaxPort)
	conn, err1 := _dialer.Dial("udp", tunDns.srcDns)
	if err1 == nil {
		defer conn.Close()
		//windows 使用虚拟udp不然会被劫持
		dnsClientConn := new(dns.Conn)
		dnsClientConn.Conn = conn
		dnsClientConn.UDPSize = 4096
		defer dnsClientConn.Close()
		return tunDns.dnsClient.ExchangeWithConn(m, dnsClientConn)
	}
	return nil, 0, errors.New("port use.")
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
	v, err := tunDns.ipv4Res(domain)
	if err == nil {
		m.Answer = []dns.RR{v}
	}
	// final
	return m, err
}

/*ipv6查询代理*/
func (tunDns *TunDns) doIPv6Query(r *dns.Msg) (*dns.Msg, error) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Authoritative = false
	domain := r.Question[0].Name
	v, err := tunDns.ipv6Res(domain)
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
		msg, rtt, err = tunDns.Exchange(r)
		log.Printf("ServeDNS default rtt:%+v err:%+v\r\n", rtt, err)
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
	_, excludeFlag := tunDns.excludeDomains.Load(domain)

	if ok && !excludeFlag && strings.HasPrefix(ipLog, tunAddr[0:4]) {
		ip = ipLog
		ipTtl = 1
	} else {
		if _ip == nil && len(domain) > 0 {
			//为空的话智能dns的话先解析一遍
			var backIp net.IP
			backIp, _, err := tunDns.localResolve(domain, 4)
			if err == nil {
				_ip = backIp
			} else if err.Error() != "Not found addr" {
				log.Printf("local dns error:%v\r\n", err)
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
		if excludeFlag || (_ip != nil && (comm.IsChinaMainlandIP(_ip.String()) || !comm.IsPublicIP(_ip))) {
			//中国Ip直接回复
			if _ip != nil {
				ip = _ip.String()
			}
		} else if !excludeFlag && !dnsErr {
			//外国随机分配一个代理ip
			ip = tunDns.allocIpByDomain(domain)
			ipTtl = 1
		}
	}
	log.Printf("domain:%s ip:%s backErr:%+v\r\n", domain, ip, backErr)
	return &dns.A{
		Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ipTtl},
		A:   net.ParseIP(ip),
	}, backErr
}

/*dns缓存自动清理*/
func (tunDns *TunDns) clearDnsCache() {
	for tunDns.run {
		dnsCache.Free()
		time.Sleep(time.Second * 60)
	}
}

/*检测旧dns改变*/
func (tunDns *TunDns) checkDnsChange() {
	for tunDns.run {
		conn, err := net.DialTimeout("tcp", tunDns.srcDns, time.Second*1)
		//可能dns变了，
		if err != nil {
			oldDns := comm.GetUseDns(tunDns.dnsAddr, tunGW, "")
			//检测网关DNS是否改变
			if strings.Index(tunDns.srcDns, oldDns) == -1 {
				tunDns.srcDns = oldDns + ":53"
			}
		} else {
			conn.Close()
		}
		time.Sleep(time.Second * 10)
	}
}

/*ipv6智能判断*/
func (tunDns *TunDns) ipv6Res(domain string) (interface{}, error) {
	ipLog, ok := tunDns.ip2Domain.GetInverse(domain)
	_, ok1 := ipv6To4.Load(domain)
	//_, excludeFlag := tunDns.excludeDomains[domain]
	if ok && ok1 && strings.HasPrefix(ipLog, tunAddr[0:4]) {
		//ipv6返回错误迫使使用ipv4地址
		return nil, errors.New("use ipv4")
	}

	//ipv6
	ipStr, rtt, err := tunDns.localResolve(domain, 6)
	log.Printf("ipv6:%s  rtt:%+v err:%+v\r\n", domain, rtt, err)
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
	m1, rtt, err := tunDns.Exchange(query)
	var loopIp = ""
	if err == nil {
		for _, v := range m1.Answer {
			if ipType == 4 {
				record, isType := v.(*dns.A)
				if isType {
					//有些dns会返回127.0.0.1
					if record.A.String() != "127.0.0.1" {
						dnsCache.WriteDnsCache(domain+":"+strconv.Itoa(ipType), record.Hdr.Ttl, record.A.String())
						return record.A, record.Hdr.Ttl, nil
					} else {
						loopIp = record.A.String()
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
		log.Printf("localResolve:%s  ipType:%d  rtt:%+v err:%+v\r\n", domain, ipType, rtt, err)
		return nil, 0, err
	}
	if loopIp == "127.0.0.1" {
		return nil, 0, nil
	}
	return nil, 0, errors.New("Not found addr")
}

func (tunDns *TunDns) StartSmartDns() {
	tunDns.run = true
	tunDns.udpServer = &dns.Server{
		Net:          "udp4",
		Addr:         tunDns.dnsAddr + ":" + tunDns.dnsPort,
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}
	tunDns.tcpServer = &dns.Server{
		Net:          "tcp4",
		Addr:         tunDns.dnsAddr + ":" + tunDns.dnsPort,
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}

	tunDns.dnsClient = &dns.Client{
		Net:            "udp",
		UDPSize:        4096,
		SingleInflight: false,
		ReadTimeout:    time.Duration(10) * time.Second,
		WriteTimeout:   time.Duration(10) * time.Second,
	}

	tunDns.srcDns = comm.GetUseDns(tunDns.dnsAddr, tunGW, "") + ":53"
	go tunDns.udpServer.ListenAndServe()
	go tunDns.tcpServer.ListenAndServe()
	go tunDns.checkDnsChange()
	go tunDns.clearDnsCache()
}

/*给域名分配私有地址*/
func (tunDns *TunDns) allocIpByDomain(domain string) string {
	var ip = ""
	for i := 0; i <= 5; i++ {
		ip = comm.GetCidrRandIpByNet(tunAddr, tunMask)
		_, ok := tunDns.ip2Domain.Get(ip)
		if !ok && ip != tunAddr {
			tunDns.ip2Domain.Insert(ip, domain)
			break
		} else {
			log.Println("ip used up")
			ip = ""
		}
	}
	return ip
}
