package dot

import (
	"crypto/tls"
	"errors"
	"github.com/miekg/dns"
	"goSocksTap/comm/socks"
	"sync"
	"net"
	"strconv"
	"strings"
	"time"
)

var dnsCache *DnsCache

type DoT struct {
	Addr string;
	LSocks string;
	ServerName string;
	dnsClient *dns.Client
	dnsClientConn *dns.Conn
	connect bool;
}

func init(){
	dnsCache = &DnsCache{cache: make(map[string]string, 128)}
}


func (rd *DoT)Connect() error {
	rd.dnsClient = &dns.Client{
		Net:          "tcp",
		UDPSize:      4096,
		SingleInflight:true,
		ReadTimeout:  time.Duration(3) * time.Second,
		WriteTimeout: time.Duration(2) * time.Second,
	}
	if rd.ServerName == "" {
		return errors.New("dot: server name cannot be empty")
	}
	if rd.Addr == "" {
		return errors.New("dot: addrs cannot be empty")
	}
	cfg := &tls.Config{
		ServerName: rd.ServerName,
	}
	srcConn, err := net.DialTimeout("tcp", rd.LSocks, time.Second*15)
	if err != nil {
		return  err;
	}
	if rd.LSocks!="" {
		if socks.SocksCmd(srcConn, 1, uint8(0x01), rd.Addr) != nil {
			return errors.New("local socks error")
		}
	}
	srcConn.(*net.TCPConn).SetKeepAlive(true)
	srcConn.(*net.TCPConn).SetKeepAlivePeriod(3 * time.Minute)


	rd.dnsClientConn = new(dns.Conn)
	rd.dnsClientConn.Conn= tls.Client(srcConn, cfg)
	rd.dnsClientConn.UDPSize = 4094;
	rd.connect=true;
	return nil;
}



func (rd *DoT)Resolve(remoteHost string) (string,error){
	if !rd.connect{
		rd.Connect();
	}
	var ip="";
	var err error
	cache:= readDnsCache(remoteHost)
	if cache!="" {
		return  cache,nil;
	}
	query := &dns.Msg{}
	query.SetQuestion(remoteHost+".", dns.TypeA)
	response,_,err:=rd.dnsClient.ExchangeWithConn(query,rd.dnsClientConn)
	if err!=nil{
		return "",err;
	}
	if err==nil {
		for _, v := range response.Answer {
			record, isType := v.(*dns.A)
			if isType {
				ip=record.A.String();
				writeDnsCache(remoteHost,ip);
				break;
			}
		}
	}
	return ip,err;
}

type DnsCache struct {
	cache        map[string]string;
	sync.Mutex
}
func readDnsCache(remoteHost string)string{
	dnsCache.Lock();
	defer dnsCache.Unlock();
	if v, ok := dnsCache.cache[remoteHost]; ok {
		cache:=strings.Split(v,"_")
		cacheTime, _ := strconv.ParseInt(cache[1], 10, 64)
		//60ms
		if time.Now().Unix()-cacheTime<3*60 {
			return cache[0];
		}
	}
	return "";
}
func writeDnsCache(remoteHost string,ip string)string{
	dnsCache.Lock();
	defer dnsCache.Unlock();
	dnsCache.cache[remoteHost]=ip+"_"+strconv.FormatInt(time.Now().Unix(),10)
	return "";
}
