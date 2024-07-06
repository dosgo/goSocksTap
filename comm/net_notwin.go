//go:build !windows
// +build !windows

package comm

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/songgao/water"
)

var oldDns = ""

func GetDnsServer() []string {
	dns := []string{}
	return dns
}

func GetLocalAddresses() ([]lAddr, error) {
	lAddrs := []lAddr{}
	return lAddrs, nil
}

func GetWaterConf(tunAddr string, tunMask string) water.Config {
	config := water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "tun2"
	return config
}

func SetNetConf(dnsIpv4 string) {
	var dnsByte = []byte("nameserver " + dnsIpv4 + "\n")
	oldByte, _ := os.ReadFile("/etc/resolv.conf")
	dnss := strings.Split(string(oldByte), "\n")
	var reDnsStr = ""
	for _, _dns := range dnss {
		if strings.Index(_dns, dnsIpv4) != -1 {
			continue
		} else {
			reDnsStr += _dns + "\n"
		}
	}
	reDnsStr = string(dnsByte) + reDnsStr
	os.WriteFile("/etc/resolv.conf", []byte(reDnsStr), os.ModePerm)
}

/*获取旧的dns,内网解析用*/
func GetUseDns(dnsAddr string, tunGW string, _tunGW string) string {
	if len(oldDns) > 0 {
		return oldDns
	}
	oldByte, _ := os.ReadFile("/etc/resolv.conf")
	dnss := strings.Split(string(oldByte), "\n")
	for _, _dns := range dnss {
		if strings.Index(_dns, dnsAddr) != -1 {
			continue
		} else if strings.Index(_dns, "nameserver") != -1 {
			oldDns = strings.TrimSpace(strings.Replace(_dns, "nameserver", "", -1))
			// 执行DNS查询
			if checkDns(oldDns) {
				return oldDns
			}
		}
	}
	return "114.114.114.114"
}

func checkDns(dnsServer string) bool {
	domain := "www.taobao.com" // 替换为你要查询的域名
	qtype := dns.TypeA         // 替换为你要执行的查询类型
	// 创建DNS消息
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	// 创建DNS客户端
	client := new(dns.Client)
	// 执行DNS查询
	response, _, err := client.Exchange(msg, dnsServer+":53")
	if err != nil {
		return false
	}
	if response.Rcode != dns.RcodeSuccess {
		return false
	}
	return true
}

func ResetNetConf(ip string) {
	oldByte, _ := os.ReadFile("/etc/resolv.conf")
	dnss := strings.Split(string(oldByte), "\n")
	var reDnsStr = ""
	for _, _dns := range dnss {
		if strings.Index(_dns, ip) != -1 {
			continue
		} else {
			reDnsStr += _dns + "\n"
		}
	}
	os.WriteFile("/etc/resolv.conf", []byte(reDnsStr), os.ModePerm)
}

func CmdHide(name string, arg ...string) *exec.Cmd {
	return exec.Command(name, arg...)
}
func GetPortDialer(min int, max int) *net.Dialer {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}
	return dialer
}
