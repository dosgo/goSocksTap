// +build windows

package comm

import (
	"github.com/StackExchange/wmi"
	"github.com/songgao/water"
	routetable "github.com/yijunjun/route-table"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"fmt"
	"unsafe"
)


func GetGateway()string {
	table, err := routetable.NewRouteTable()
	if err != nil {
		return "";
	}
	defer table.Close()
	rows, err := table.Routes()
	if err != nil {
		return "";
	}
	var minMetric uint32=0;
	var gwIp="";
	for _, row := range rows {
		if routetable.Inet_ntoa(row.ForwardDest, false)=="0.0.0.0" {

			if minMetric==0 {
				minMetric=row.ForwardMetric1;
				gwIp=routetable.Inet_ntoa(row.ForwardNextHop, false);
			}else{
				if row.ForwardMetric1<minMetric {
					minMetric=row.ForwardMetric1;
					gwIp=routetable.Inet_ntoa(row.ForwardNextHop, false);
				}
			}
		}
	}
	return gwIp;
}



/*获取旧的dns,内网解析用*/
func GetUseDns(dnsAddr string,tunGW string,_tunGW string) string{
	gwIp:=GetGateway();
	dnsServers,_,_:=GetDnsServerByGateWay(gwIp);
	for _,v:=range dnsServers{
		if v!=dnsAddr&&v!=tunGW && v!=_tunGW  {
			return v;
		}
	}
	return "114.114.114.114";
}



func GetDnsServerByGateWay(gwIp string)([]string,bool,bool){
	//DNSServerSearchOrder
	adapters,err:=GetNetworkAdapter()
	var isIpv6=false;
	if err!=nil {
		return nil,false,isIpv6;
	}
	for _,v:=range adapters{
		if len(v.DefaultIPGateway)>0&&v.DefaultIPGateway[0]==gwIp {
			for _,v2:=range v.IPAddress{
				if len(v2)>16{
					isIpv6=true;
					break;
				}
			}
			return v.DNSServerSearchOrder,v.DHCPEnabled,isIpv6;
		}
	}
	return nil,false,isIpv6;
}


type NetworkAdapter struct {
	DNSServerSearchOrder   []string
	DefaultIPGateway []string
	IPAddress []string
	Caption    string
	DHCPEnabled  bool
	ServiceName  string
	IPSubnet   []string
	SettingID string
}

func GetWaterConf(tunAddr string,tunMask string)water.Config{
	masks:=net.ParseIP(tunMask).To4();
	maskAddr:=net.IPNet{IP: net.ParseIP(tunAddr), Mask: net.IPv4Mask(masks[0], masks[1], masks[2], masks[3] )}
	return  water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID:   "tap0901",
			Network:       maskAddr.String(),
		},
	}
}

func GetNetworkAdapter() ([]NetworkAdapter,error){
	var s = []NetworkAdapter{}
	err := wmi.Query("SELECT Caption,SettingID,DNSServerSearchOrder,DefaultIPGateway,ServiceName,IPAddress,IPSubnet,DHCPEnabled       FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True", &s) // WHERE (BIOSVersion IS NOT NULL)
	if err != nil {
		log.Printf("err:%v\r\n",err)
		return nil,err
	}
	return s,nil;
}
func SetNetConf(dnsIpv4 string,dnsIpv6 string){

}

func ResetNetConf(ip string){

}



func CmdHide(name string, arg ...string) *exec.Cmd{
	cmd:=exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd;
}



func getAdapterList() (*syscall.IpAdapterInfo, error) {
	b := make([]byte, 1000)
	l := uint32(len(b))
	a := (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
	err := syscall.GetAdaptersInfo(a, &l)
	if err == syscall.ERROR_BUFFER_OVERFLOW {
		b = make([]byte, l)
		a = (*syscall.IpAdapterInfo)(unsafe.Pointer(&b[0]))
		err = syscall.GetAdaptersInfo(a, &l)
	}
	if err != nil {
		return nil, os.NewSyscallError("GetAdaptersInfo", err)
	}
	return a, nil
}

func GetLocalAddresses() ([]lAddr ,error) {
	lAddrs := []lAddr{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil,err
	}

	aList, err := getAdapterList()
	if err != nil {
		return nil,err
	}


	for _, ifi := range ifaces {
		for ai := aList; ai != nil; ai = ai.Next {
			index := ai.Index
			if ifi.Index == int(index) {
				ipl := &ai.IpAddressList
				gwl := &ai.GatewayList
				for ; ipl != nil; ipl = ipl.Next  {
					itemAddr := lAddr{}
					itemAddr.Name=ifi.Name
					itemAddr.IpAddress=fmt.Sprintf("%s",ipl.IpAddress.String)
					itemAddr.IpMask=fmt.Sprintf("%s",ipl.IpMask.String)
					itemAddr.GateWay=fmt.Sprintf("%s",gwl.IpAddress.String)
					lAddrs=append(lAddrs,itemAddr)
				}
			}
		}
	}
	return lAddrs,err
}