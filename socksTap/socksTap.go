package socksTap

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/vishalkuo/bimap"
	"goSocksTap/comm"
	"goSocksTap/comm/dot"
	"goSocksTap/comm/netstat"
	"goSocksTap/comm/socks"
	"goSocksTap/comm/tun2socks"
	"goSocksTap/winDivert"
	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)


var dnsCache *comm.DnsCache

func init(){
	dnsCache = &comm.DnsCache{Cache: make(map[string]string, 128)}
}
type SocksTap struct {
	localSocks string;
	udpLimit sync.Map;
	run bool;
	tunDns *TunDns
	safeDns *dot.DoT
	socksServerPid int
	autoFilter bool
	tunDev io.ReadWriteCloser
}

type TunDns struct {
	dnsClient *dns.Client
	dnsClientConn *dns.Conn
	udpServer  *dns.Server
	tcpServer  *dns.Server
	smartDns int;
	excludeDomains []string
	dnsAddr string;
	dnsAddrV6 string;
	dnsPort string;
	ip2Domain *bimap.BiMap
	singleflight   *singleflight.Group
}


var tunAddr ="10.0.0.2";
var tunGW ="10.0.0.1";
var tunMask="255.255.0.0"
var fakeUdpNat sync.Map


func (fakeDns *SocksTap)Start(localSocks string,excludeDomain string,autoFilter bool) {
	fakeDns.localSocks=localSocks;
	if runtime.GOOS=="windows" {
		if excludeDomain=="" {
			fakeDns.autoFilter=true;
		}else {
			fakeDns.autoFilter = autoFilter;
		}
		fakeDns.socksServerPid, _ = netstat.PortGetPid(localSocks)
	}

	fakeDns.safeDns= &dot.DoT{ServerName:"dns.google",Addr:"8.8.8.8:853",LSocks:localSocks}
	fakeDns.safeDns.Connect();

	//start local dns
	fakeDns.tunDns =&TunDns{smartDns:1,dnsPort:"53",dnsAddr:"127.0.0.1",dnsAddrV6:"0:0:0:0:0:0:0:1"};
	fakeDns.tunDns.ip2Domain= bimap.NewBiMap()
	fakeDns.tunDns.singleflight  = &singleflight.Group{}
	fakeDns.tunDns.excludeDomains=make([]string,0)
	if excludeDomain!="" {
		fakeDns.tunDns.excludeDomains=append(fakeDns.tunDns.excludeDomains,excludeDomain+".")
	}

	//生成本地udp端口避免过滤的时候变动了
	clientPort,_:=comm.GetFreeUdpPort();
	fakeDns.tunDns._startSmartDns(clientPort)

	//edit DNS
	if runtime.GOOS!="windows" {
		comm.SetNetConf(fakeDns.tunDns.dnsAddr, fakeDns.tunDns.dnsAddrV6);
	}
	fakeDns._startTun(1500);
	if runtime.GOOS=="windows" {
		go winDivert.RedirectDNS(fakeDns.tunDns.dnsAddr,fakeDns.tunDns.dnsPort,clientPort);
	}
	//udp limit auto remove
	fakeDns.run=true;
	go fakeDns.task();
}

func (fakeDns *SocksTap)Shutdown(){
	if fakeDns.tunDev!=nil {
		fakeDns.tunDev.Close();
	}
	if fakeDns.tunDns!=nil {
		comm.ResetNetConf(fakeDns.tunDns.dnsAddr);
		fakeDns.tunDns.Shutdown();
	}
	fakeDns.run=false;
	winDivert.CloseWinDivert();
}



func (fakeDns *SocksTap) _startTun(mtu int) (error){
	tunAddr, tunGW = comm.GetUnusedTunAddr();
	var err error
	fakeDns.tunDev, err = comm.RegTunDev("",tunAddr,tunMask,tunGW,"")
	if err != nil {
		return err;
	}
	go func() {
		time.Sleep(time.Second*1)
		comm.AddRoute(tunAddr, tunGW, tunMask)
	}()
	go tun2socks.ForwardTransportFromIo(fakeDns.tunDev,mtu,fakeDns.tcpForwarder,fakeDns.udpForwarder);
	return nil;
}
func (fakeDns *SocksTap) task(){
	for fakeDns.run{
		fakeDns.udpLimit.Range(func(k, v interface{}) bool {
			_v:=v.(*comm.UdpLimit);
			if _v.Expired<time.Now().Unix() {
				fakeDns.udpLimit.Delete(k)
			}
			return true
		})
		if runtime.GOOS=="windows" {
			pid, err := netstat.PortGetPid(fakeDns.localSocks)
			if err == nil && pid > 0 {
				fakeDns.socksServerPid = pid;
			}
		}
		time.Sleep(time.Second*30);
	}
}

func (fakeDns *SocksTap) tcpForwarder(conn *gonet.TCPConn)error{
	var srcAddr=conn.LocalAddr().String();
	var srcAddrs=strings.Split(srcAddr,":")
	var remoteAddr="";
	var addrType =0x01;
	defer  conn.Close();
	if fakeDns.autoFilter && netstat.IsSocksServerAddr(fakeDns.socksServerPid,srcAddrs[0])  {
		domain := fakeDns.dnsToDomain(srcAddr)
		domains:=strings.Split(domain,":")
		fmt.Printf("IsSocksServerAddr:%d  addr:%s domain:%s\r\n",fakeDns.socksServerPid,srcAddrs[0],domains[0])
		if domain==""{
			fmt.Printf("dnsToDomain domain:%s srcAddr:%s\r\n",domain,srcAddr)
			return nil;
		}
		//add exclude  domain
		fakeDns.tunDns.excludeDomains=append(fakeDns.tunDns.excludeDomains,domains[0])
		query := &dns.Msg{}
		query.SetQuestion(domains[0], dns.TypeA)
		ip,_,err:=fakeDns.tunDns.localResolve(query)
		if err!=nil{
			fmt.Printf("domain:%s  srcAddr:%s localResolve err:%s\r\n",domains[0],srcAddr,err)
			return nil;
		}
		socksConn, err:= net.DialTimeout("tcp", ip.String()+":"+srcAddrs[1], time.Second*15)
		if err != nil {
			return nil
		}
		defer socksConn.Close();
		comm.TcpPipe(conn, socksConn, time.Minute*5)
	}else {
		remoteAddr = fakeDns.dnsToAddr(srcAddr)
		if remoteAddr==""{
			fmt.Printf("remoteAddr:%s srcAddr:%s\r\n",remoteAddr,srcAddr)
			return nil;
		}
		socksConn, err := net.DialTimeout("tcp", fakeDns.localSocks, time.Second*15)
		if err != nil {
			log.Printf("err:%v", err)
			return nil
		}
		defer socksConn.Close();
		if socks.SocksCmd(socksConn, 1, uint8(addrType), remoteAddr) == nil {
			comm.TcpPipe(conn, socksConn, time.Minute*5)
		}
	}
	return nil
}

func (fakeDns *SocksTap) udpForwarder(conn *gonet.UDPConn, ep tcpip.Endpoint)error{
	var srcAddr=conn.LocalAddr().String();
	var remoteAddr="";
	remoteAddr = fakeDns.dnsToAddr(srcAddr)
	if remoteAddr==""{
		conn.Close();
		return nil;
	}

	socksConn, err := net.DialTimeout("tcp", fakeDns.localSocks, time.Second*15)
	if err == nil {
		defer socksConn.Close();
		gateWay,err:=socks.GetUdpGate(socksConn,remoteAddr);
		fmt.Printf("gateWay:%s %v\r\n",gateWay,err)
		if err==nil {
			defer ep.Close();
			dstAddr,_:=net.ResolveUDPAddr("udp",remoteAddr)
			fmt.Printf("udp-remoteAddr:%s\r\n",remoteAddr)
			socks.SocksUdpGate(conn,gateWay,dstAddr);
		}else{
			fakeDns.UdpDirect(remoteAddr,conn,ep);
		}
	}else{
		fakeDns.UdpDirect(remoteAddr,conn,ep);
	}
	return nil;
}

/*直连*/
func (fakeDns *SocksTap) UdpDirect(remoteAddr string,conn *gonet.UDPConn, ep tcpip.Endpoint ){
	//tuntype 直连
	var limit *comm.UdpLimit;
	_limit,ok:=fakeDns.udpLimit.Load(remoteAddr)
	if !ok{
		limit=&comm.UdpLimit{Limit: rate.NewLimiter(rate.Every(1 * time.Second), 50),Expired: time.Now().Unix()+5}
	}else{
		limit=_limit.(*comm.UdpLimit);
	}
	//限流
	if limit.Limit.Allow(){
		limit.Expired=time.Now().Unix()+5;
		//本地直连交换
		comm.TunNatSawp(&fakeUdpNat, conn,ep, remoteAddr, 65*time.Second);
		fakeDns.udpLimit.Store(remoteAddr,limit);
	}
}


/*dns addr swap*/
func (fakeDns *SocksTap) dnsToAddr(remoteAddr string) string{
	remoteAddr=fakeDns.dnsToDomain(remoteAddr)
	if remoteAddr=="" {
		return "";
	}
	remoteAddrs:=strings.Split(remoteAddr,":")
	domain:=remoteAddrs[0]
	ip, err := fakeDns.safeDns.Resolve(domain[0 : len(domain)-1])
	if err!=nil{
		return "";
	}
	return ip+":"+remoteAddrs[1]
}


/*dns addr swap*/
func (fakeDns *SocksTap) dnsToDomain(remoteAddr string) string{
	if fakeDns.tunDns==nil {
		return "";
	}
	remoteAddrs:=strings.Split(remoteAddr,":")
	_domain,ok:= fakeDns.tunDns.ip2Domain.Get(remoteAddrs[0])
	if !ok{
		return "";
	}
	return _domain.(string)+":"+remoteAddrs[1]
}


func (tunDns *TunDns)_startSmartDns(clientPort string)  {
	tunDns.udpServer = &dns.Server{
		Net:          "udp",
		Addr:         ":"+tunDns.dnsPort,
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}
	tunDns.tcpServer= &dns.Server{
		Net:          "tcp",
		Addr:         ":"+tunDns.dnsPort,
		Handler:      dns.HandlerFunc(tunDns.ServeDNS),
		UDPSize:      4096,
		ReadTimeout:  time.Duration(10) * time.Second,
		WriteTimeout: time.Duration(10) * time.Second,
	}

	localPort, _ := strconv.Atoi(clientPort)
	netAddr := &net.UDPAddr{Port:localPort}
	_Dialer := &net.Dialer{Timeout:3*time.Second,LocalAddr: netAddr}
	tunDns.dnsClient = &dns.Client{
		Net:          "udp",
		UDPSize:      4096,
		Dialer: _Dialer,
		SingleInflight:true,
		ReadTimeout:  time.Duration(3) * time.Second,
		WriteTimeout: time.Duration(2) * time.Second,
	}
	tunDns.dnsClientConn,_=tunDns.dnsClient.Dial( comm.GetUseDns(tunDns.dnsAddr, tunGW,"")+":53");
	go tunDns.udpServer.ListenAndServe();
	go tunDns.tcpServer.ListenAndServe();
}

func (tunDns *TunDns)Shutdown(){
	if tunDns.tcpServer!=nil {
		tunDns.tcpServer.Shutdown();
	}
	if tunDns.udpServer!=nil {
		tunDns.udpServer.Shutdown();
	}
}




func (tunDns *TunDns) doIPv4Query(r *dns.Msg) (*dns.Msg, error) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Authoritative = false
	domain := r.Question[0].Name
	v, _, _ := tunDns.singleflight.Do(domain, func() (interface{}, error) {
		return tunDns.ipv4Res(domain,r);
	})
	m.Answer =v.( []dns.RR )
	// final
	return m, nil
}
func  (tunDns *TunDns)ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var msg *dns.Msg
	var err error
	switch r.Question[0].Qtype {
	case  dns.TypeA:
		msg, err = tunDns.doIPv4Query(r)
		break;
	case  dns.TypeAAAA:
		//ipv6
		msg, err = tunDns.resolve(r)
		break;
	default:
		msg,_,err = tunDns.dnsClient.ExchangeWithConn(r,tunDns.dnsClientConn)
		break;
	}
	if err != nil {
		dns.HandleFailed(w, r)
	} else {
		w.WriteMsg(msg)
	}
}





/*ipv4智能响应*/
func (tunDns *TunDns)ipv4Res(domain string,r *dns.Msg) ([]dns.RR,error) {
	var _ip  net.IP;
	var ip ="";
	var ipTtl uint32=60;
	var dnsErr=false;
	ipLog,ok :=tunDns.ip2Domain.GetInverse(domain)
	if ok && !comm.ArrMatch(domain,tunDns.excludeDomains) && strings.HasPrefix(ipLog.(string), tunAddr[0:4]) {
		ip=ipLog.(string);
		ipTtl=1;
	}else {
		if _ip==nil && r!=nil  {
			//为空的话智能dns的话先解析一遍
			if tunDns.smartDns==1  {
				m1,_,err := tunDns.localResolve(r)
				if err == nil {
					_ip=m1;
				}else if err.Error()!="Not found addr" {
					fmt.Printf("local dns error:%v\r\n",err)
					oldDns:=comm.GetUseDns(tunDns.dnsAddr, tunGW,"");
					//检测网关DNS是否改变
					if strings.Index(tunDns.dnsClientConn.RemoteAddr().String(),oldDns)==-1 {
						tunDns.dnsClientConn.Close();
						dnsClientConn,err:=tunDns.dnsClient.Dial(oldDns+":53");
						if err==nil {
							tunDns.dnsClientConn=dnsClientConn;
						}
					}
					//解析错误说明无网络,否则就算不存在也会回复的
					dnsErr=true;//标记为错误
				}
			}
		}

		//不为空判断是不是中国ip
		if   comm.ArrMatch(domain,tunDns.excludeDomains)|| (_ip!=nil && (comm.IsChinaMainlandIP(_ip.String()) || !comm.IsPublicIP(_ip))) {
			//中国Ip直接回复
			if _ip!=nil {
				ip = _ip.String();
			}
		} else if !comm.ArrMatch(domain,tunDns.excludeDomains) &&!dnsErr {
			//外国随机分配一个代理ip
			for i := 0; i <= 2; i++ {
				ip = comm.GetCidrRandIpByNet(tunAddr, tunMask)
				_, ok := tunDns.ip2Domain.Get(ip)
				if !ok && ip!= tunAddr {
					ipTtl=1;
					tunDns.ip2Domain.Insert(ip, domain)
					break;
				} else {
					fmt.Println("ip used up")
					ip = "";
				}
			}
		}
	}


	fmt.Printf("domain:%s ip:%s srcIp:%s\r\n",domain,ip, _ip.String())
	return []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ipTtl},
		A:   net.ParseIP(ip),
	}},nil;
}

func  (tunDns *TunDns)resolve(r *dns.Msg) (*dns.Msg, error) {
	m :=  &dns.Msg{}
	m.SetReply(r)
	m.Authoritative = false
	domain := r.Question[0].Name
	//ipv6
	m1,_,err :=	tunDns.dnsClient.ExchangeWithConn(r,tunDns.dnsClientConn)
	fmt.Printf("ipv6:%s err:%+v\r\n",domain,err)
	if err == nil {
		return m1,nil;
	}
	return m, err;
}

/*本地dns解析有缓存*/
func  (tunDns *TunDns)localResolve(r *dns.Msg) (net.IP,uint32, error) {
	domain := r.Question[0].Name
	cache,ttl:= dnsCache.ReadDnsCache(domain)
	if cache!="" {
		return net.ParseIP(cache), ttl,nil;
	}

	m1,_,err := tunDns.dnsClient.ExchangeWithConn(r,tunDns.dnsClientConn)
	if err == nil {
		for _, v := range m1.Answer {
			record, isType := v.(*dns.A)
			if isType {
				//有些dns会返回127.0.0.1
				if record.A.String() != "127.0.0.1" {
					dnsCache.WriteDnsCache(domain,record.Hdr.Ttl,record.A.String())
					return  record.A, record.Hdr.Ttl,nil;
				}
			}
		}
	}else{
		return nil,0,err;
	}
	return nil,0,errors.New("Not found addr")
}

