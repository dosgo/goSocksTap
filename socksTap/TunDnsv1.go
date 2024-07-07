package socksTap

import (
	"errors"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/miekg/dns"
	"github.com/vishalkuo/bimap"
)

type TunDnsV1 struct {
	dnsClient *dns.Client
	srcDns    string
	run       bool
	udpServer *dns.Server
	//excludeDomains      map[string]uint8
	excludeDomains sync.Map
	dnsAddr        string
	dnsPort        string
	ip2Domain      *bimap.BiMap[string, string]
	sendMinPort    int
	sendMaxPort    int
}

func (tunDns *TunDnsV1) Exchange(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	if runtime.GOOS != "windows" {
		return tunDns.dnsClient.Exchange(m, tunDns.srcDns)
	}
	_dialer := comm.GetPortDialer(tunDns.sendMinPort, tunDns.sendMaxPort)
	conn, err := _dialer.Dial("udp", tunDns.srcDns)
	if err == nil {
		defer conn.Close()
		dnsClientConn := new(dns.Conn)
		dnsClientConn.Conn = conn
		dnsClientConn.UDPSize = 4096
		defer dnsClientConn.Close()
		return tunDns.dnsClient.ExchangeWithConn(m, dnsClientConn)
	}
	return nil, 0, errors.New("port use.")
}

func (tunDns *TunDnsV1) Shutdown() {
	tunDns.run = false
	if tunDns.udpServer != nil {
		tunDns.udpServer.Shutdown()
	}
}

/*检测旧dns改变*/
func (tunDns *TunDnsV1) checkDnsChange() {
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

func (tunDns *TunDnsV1) StartSmartDns() {
	tunDns.run = true
	tunDns.udpServer = &dns.Server{
		Net:          "udp4",
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
	go tunDns.checkDnsChange()
}

func (tunDns *TunDnsV1) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	domain := r.Question[0].Name
	ipLog, ok := tunDns.ip2Domain.GetInverse(domain)
	var response *dns.Msg
	var err error
	_, excludeFlag := tunDns.excludeDomains.Load(domain)
	if ok && !excludeFlag && r.Question[0].Qtype == dns.TypeA {
		response = tunDns.overrideResponse(r, ipLog, 1)
	} else {
		if excludeFlag {
			tunDns.ip2Domain.DeleteInverse(domain)
		}
		// 转发请求到目标 DNS 服务器
		response, _, err = tunDns.Exchange(r)
		if err != nil {
			log.Println("ServeDNS err:" + err.Error())
			return
		}
		// 修改特定 IP 的响应
		tunDns.modifyResponse(response, domain)
	}

	if err != nil {
		response.SetRcode(r, dns.RcodeServerFailure)
	}
	w.WriteMsg(response)
}

func (tunDns *TunDnsV1) overrideResponse(msg *dns.Msg, ip string, ttl uint32) *dns.Msg {
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

func (tunDns *TunDnsV1) modifyResponse(msg *dns.Msg, domain string) {
	for i, ans := range msg.Answer {
		switch a := ans.(type) {
		case *dns.A:
			srcIp := a.A.String()
			_, excludeFlag := tunDns.excludeDomains.Load(domain)
			//不是中国ip,又不是排除的ip
			if !excludeFlag && !comm.IsChinaMainlandIP(srcIp) && comm.IsPublicIP(a.A) {
				ip := tunDns.allocIpByDomain(domain)
				a.A = net.ParseIP(ip)
				a.Hdr.Ttl = 1
				msg.Answer[i] = a
			}
		case *dns.AAAA:
			//if a.AAAA.String() == specificIP {
			//a.AAAA = net.ParseIP(specificIP)
			//}
		}
	}
	msg.Authoritative = false
}

/*给域名分配私有地址*/
func (tunDns *TunDnsV1) allocIpByDomain(domain string) string {
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

/*
本地dns解析有缓存
domain 域名有最后一个"."
*/
func (tunDns *TunDnsV1) localResolve(domain string, ipType int) (net.IP, uint32, error) {
	query := &dns.Msg{}
	if ipType == 4 {
		query.SetQuestion(domain, dns.TypeA)
	}
	if ipType == 6 {
		query.SetQuestion(domain, dns.TypeAAAA)
	}
	response, _, _ := tunDns.Exchange(query)
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