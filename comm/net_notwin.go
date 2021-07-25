// +build !windows

package comm

import (
	"github.com/songgao/water"
	"os"
	"os/exec"
	"strings"
)
var oldDns="";



func GetGateway()string {
	return "";
}

func GetDnsServer() []string {
	dns := []string{}
	return dns;
}


func GetLocalAddresses() ([]lAddr ,error) {
	lAddrs := []lAddr{}
	return lAddrs,nil;
}


func GetWaterConf(tunAddr string,tunMask string)water.Config{
	config:=  water.Config{
		DeviceType: water.TUN,
	}
	config.Name = "tun2"
	return config;
}


func SetNetConf(dnsIpv4 string,dnsIpv6 string){
	var dnsByte=[]byte("nameserver "+dnsIpv4+"\n");
	oldByte,_:=os.ReadFile("/etc/resolv.conf")
	dnsByte=append(dnsByte,oldByte...)
	os.WriteFile("/etc/resolv.conf",dnsByte,os.ModePerm)
}


/*获取旧的dns,内网解析用*/
func GetUseDns(dnsAddr string,tunGW string,_tunGW string) string{
	if len(oldDns)>0{
		return oldDns;
	}
	oldByte,_:=os.ReadFile("/etc/resolv.conf")
	dnss:=strings.Split(string(oldByte),"\n");
	for _,_dns:=range dnss{
		if  strings.Index(_dns,dnsAddr)!=-1{
			continue;
		}else{
			oldDns=strings.TrimSpace(strings.Replace(_dns,"nameserver","",-1));
			return oldDns;
		}
	}
	return "114.114.114.114";
}

func ResetNetConf(ip string){
	oldByte,_:=os.ReadFile("/etc/resolv.conf")
	dnss:=strings.Split(string(oldByte),"\n");
	var reDnsStr="";
	for _,_dns:=range dnss{
		if  strings.Index(_dns,ip)!=-1{
			continue;
		}else{
			reDnsStr+=_dns+"\n"
		}
	}
	os.WriteFile("/etc/resolv.conf",[]byte(reDnsStr),os.ModePerm)
}

func GetDnsServerByGateWay(gwIp string)([]string,bool,bool){
	oldByte,_:=os.ReadFile("/etc/resolv.conf")
	dnss:=strings.Split(string(oldByte),"\n");
	var DnsList []string;

	for _,_dns:=range dnss{
		if  strings.HasPrefix(_dns,"#"){
			continue;
		}else{
			dns:=strings.Replace(_dns,"nameserver","",-1);
			dns=strings.Trim(dns," ")
			DnsList=append(DnsList,dns)
		}
	}
	return DnsList,false,false;
}

func CmdHide(name string, arg ...string) *exec.Cmd{
	return exec.Command(name, arg...)
}
