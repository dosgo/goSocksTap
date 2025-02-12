package tunDns

import (
	"errors"
	"fmt"
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

type TunDns struct {
	srcDns         string
	dnsCache       *comm.DnsCacheV1
	run            bool
	udpServer      *dns.Server
	ExcludeDomains sync.Map
	DnsAddr        string
	DnsPort        uint16
	tunAddr        string
	tunGW          string
	tunMask        string
	Ip2Domain      *bimap.BiMap[string, string]
	SendMinPort    int
	SendMaxPort    int
	ExcludePorts   sync.Map
}

func NewTunDns(addr string, port uint16, _tunGW string, _tunMask string) *TunDns {
	tunDns := &TunDns{DnsPort: port, DnsAddr: addr, tunAddr: addr, tunGW: _tunGW, tunMask: _tunMask}
	tunDns.Ip2Domain = bimap.NewBiMap[string, string]()
	tunDns.dnsCache = &comm.DnsCacheV1{Cache: make(map[string]comm.CachedResponse, 128)}
	tunDns.SendMinPort = 600
	tunDns.SendMaxPort = 700
	if runtime.GOOS == "windows" {
		tunDns.DnsPort = 653 //为了避免死循环windows使用653端口
	}
	return tunDns
}

func (tunDns *TunDns) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	dnsClient := &dns.Client{
		Net:            "udp",
		UDPSize:        4096,
		SingleInflight: false,
		ReadTimeout:    time.Duration(10) * time.Second,
		WriteTimeout:   time.Duration(10) * time.Second,
	}
	if runtime.GOOS != "windows" {
		return dnsClient.Exchange(m, tunDns.srcDns)
	}
	_dialer := comm.GetPortDialer(tunDns.SendMinPort, tunDns.SendMaxPort)
	conn, err := _dialer.Dial("udp", tunDns.srcDns)
	if err == nil {
		defer conn.Close()
		dnsClientConn := new(dns.Conn)
		dnsClientConn.Conn = conn
		dnsClientConn.UDPSize = 4096
		defer dnsClientConn.Close()
		return dnsClient.ExchangeWithConn(m, dnsClientConn)
	}
	return nil, 0, errors.New("port use.")
}

func (tunDns *TunDns) Shutdown() {
	tunDns.run = false
	if tunDns.udpServer != nil {
		tunDns.udpServer.Shutdown()
	}
}

/*检测旧dns改变*/
func (tunDns *TunDns) checkDnsChange() {
	for tunDns.run {
		conn, err := net.DialTimeout("tcp", tunDns.srcDns, time.Second*1)
		//可能dns变了，
		if err != nil {
			oldDns := comm.GetUseDns(tunDns.DnsAddr, tunDns.tunGW, "")
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

func (tunDns *TunDns) StartSmartDns() {
	tunDns.run = true
	tunDns.udpServer = &dns.Server{
		Net:          "udp4",
		Addr:         ":" + strconv.Itoa(int(tunDns.DnsPort)),
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}

	tunDns.srcDns = comm.GetUseDns(tunDns.DnsAddr, tunDns.tunGW, "") + ":53"
	go tunDns.udpServer.ListenAndServe()
	go tunDns.checkDnsChange()
	go tunDns.clearDnsCache()
}

func (tunDns *TunDns) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	domain := r.Question[0].Name
	qtype := r.Question[0].Qtype
	ipLog, ok := tunDns.Ip2Domain.GetInverse(domain)
	var response *dns.Msg
	var err error
	log.Println("cache  allocIp dns:" + domain)
	_, excludeFlag := tunDns.ExcludeDomains.Load(domain)
	if ok && !excludeFlag && qtype == dns.TypeA {
		log.Println("cache  allocIp dns:" + domain)
		response = tunDns.overrideResponse(r, ipLog, 1)
	} else {
		if excludeFlag {
			tunDns.Ip2Domain.DeleteInverse(domain)
		}

		cacheResp := tunDns.dnsCache.ReadDnsCache(domain+fmt.Sprintf("%d", qtype), 120)

		if cacheResp == nil {
			// 转发请求到目标 DNS 服务器
			response, _, err = tunDns.Exchange(r)
			if err != nil {
				log.Println("ServeDNS domain:" + domain + " err:" + err.Error())
				return
			}
			// 修改特定 IP 的响应
			tunDns.modifyResponse(response, domain, qtype)
		} else {
			log.Println("cache dns:" + domain)
			response = cacheResp
			response.SetReply(r)
		}
	}

	if err != nil {
		response.SetRcode(r, dns.RcodeServerFailure)
	}
	w.WriteMsg(response)
}

func (tunDns *TunDns) overrideResponse(msg *dns.Msg, ip string, ttl uint32) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(msg)
	resp.Authoritative = false
	v := &dns.A{
		Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip),
	}
	resp.Answer = []dns.RR{v}
	return resp
}

func (tunDns *TunDns) modifyResponse(msg *dns.Msg, domain string, qtype uint16) {

	var isEdit = false
	for i, ans := range msg.Answer {
		switch a := ans.(type) {
		case *dns.A:
			srcIp := a.A.String()
			_, excludeFlag := tunDns.ExcludeDomains.Load(domain)
			//不是中国ip,又不是排除的ip
			if !excludeFlag && !comm.IsChinaMainlandIP(srcIp) && comm.IsPublicIP(a.A) {
				ip, ok := tunDns.Ip2Domain.GetInverse(domain)
				if !ok {
					ip = tunDns.allocIpByDomain(domain)
				}
				a.A = net.ParseIP(ip)
				a.Hdr.Ttl = 1
				msg.Answer[i] = a
				isEdit = true
			}
		case *dns.AAAA:
			//if a.AAAA.String() == specificIP {
			//a.AAAA = net.ParseIP(specificIP)
			//}
		}
	}
	//没有修改过的缓存
	if !isEdit && msg.Rcode == dns.RcodeSuccess {
		tunDns.dnsCache.WriteDnsCache(domain+fmt.Sprintf("%d", qtype), msg)
	}
	msg.Authoritative = false
}

/*给域名分配私有地址*/
func (tunDns *TunDns) allocIpByDomain(domain string) string {
	var ip = ""
	for i := 0; i <= 5; i++ {
		ip = comm.GetCidrRandIpByNet(tunDns.tunAddr, tunDns.tunMask)
		_, ok := tunDns.Ip2Domain.Get(ip)
		if !ok && ip != tunDns.tunAddr {
			tunDns.Ip2Domain.Insert(ip, domain)
			break
		} else {
			log.Println("ip used up")
			ip = ""
		}
	}
	return ip
}

/*dns缓存自动清理*/
func (tunDns *TunDns) clearDnsCache() {
	for tunDns.run {
		tunDns.dnsCache.Free(120)
		time.Sleep(time.Second * 60)
	}
}

/*
本地dns解析有缓存
domain 域名有最后一个"."
*/
func (tunDns *TunDns) LocalResolve(domain string, ipType int) (net.IP, uint32, error) {
	query := &dns.Msg{}
	if ipType == 4 {
		query.SetQuestion(domain, dns.TypeA)
	}
	if ipType == 6 {
		query.SetQuestion(domain, dns.TypeAAAA)
	}
	response, _, err := tunDns.Exchange(query)
	if err != nil {
		return nil, 0, errors.New("dns error")
	}
	// 解析DNS响应
	for _, answer := range response.Answer {
		// 如果答案是A记录（IPv4地址）
		if a, ok := answer.(*dns.A); ok {
			if ipType == 4 {
				return a.A, a.Hdr.Ttl, nil
			}
		}
		// 如果答案是AAAA记录（IPv6地址）
		if aaaa, ok := answer.(*dns.AAAA); ok {
			if ipType == 6 {
				return aaaa.AAAA, aaaa.Hdr.Ttl, nil
			}
		}
	}
	return nil, 0, errors.New("dns error")
}
func (tunDns *TunDns) ModifyDNSResponse(packet []byte) ([]byte, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(packet); err != nil {
		return packet, fmt.Errorf("解析DNS响应包失败: %v", err)
	}
	domain := msg.Question[0].Name
	isEdit := false
	for i, answer := range msg.Answer {
		if a, ok := answer.(*dns.A); ok {
			_, excludeFlag := tunDns.ExcludeDomains.Load(domain)
			//不是中国ip,又不是排除的ip
			if !excludeFlag && !comm.IsChinaMainlandIP(a.A.String()) && comm.IsPublicIP(a.A) {
				ip, ok := tunDns.Ip2Domain.GetInverse(domain)
				if !ok {
					ip = tunDns.allocIpByDomain(domain)
				}
				a.A = net.ParseIP(ip)
				a.Hdr.Ttl = 25
				msg.Answer[i] = a
				isEdit = true
			}
		}
	}
	if isEdit {
		fmt.Printf("ModifyDNSResponse domain:%s\r\n", domain)
		msg.Compress = true
		return msg.Pack()
	}
	return packet, errors.New("china ip")
}
