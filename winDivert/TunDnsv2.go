package winDivert

import (
	"log"
	"sync"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/vishalkuo/bimap"
)

type TunDnsV2 struct {
	ExcludeDomains sync.Map
	Ip2Domain      *bimap.BiMap[string, string]
}

var tunAddr = "10.0.0.2"
var tunGW = "10.0.0.1"
var tunMask = "255.255.0.0"

/*给域名分配私有地址*/
func (tunDns *TunDnsV2) AllocIpByDomain(domain string) string {
	var ip = ""
	for i := 0; i <= 5; i++ {
		ip = comm.GetCidrRandIpByNet(tunAddr, tunMask)
		_, ok := tunDns.Ip2Domain.Get(ip)
		if !ok && ip != tunAddr {
			tunDns.Ip2Domain.Insert(ip, domain)
			break
		} else {
			log.Println("ip used up")
			ip = ""
		}
	}
	return ip
}
