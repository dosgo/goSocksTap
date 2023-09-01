//go:build windows
// +build windows

package comm

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	"github.com/StackExchange/wmi"
)

/*获取旧的dns,内网解析用*/
func GetUseDns(dnsAddr string, tunGW string, _tunGW string) string {
	ifIndex := GetGatewayIndex()
	dnsServers, _, _ := GetDnsServerByIfIndex(ifIndex)
	for _, v := range dnsServers {
		if v != dnsAddr && v != tunGW && v != _tunGW {
			return v
			break
		}
	}
	return "114.114.114.114"
}

func GetDnsServerByIfIndex(ifIndex uint32) ([]string, bool, bool) {
	//DNSServerSearchOrder
	adapters, err := GetNetworkAdapter()
	var isIpv6 = false
	if err != nil {
		return nil, false, isIpv6
	}
	for _, v := range adapters {
		if v.InterfaceIndex == ifIndex {
			for _, v2 := range v.IPAddress {
				if len(v2) > 16 {
					isIpv6 = true
					break
				}
			}
			return v.DNSServerSearchOrder, v.DHCPEnabled, isIpv6
		}
	}
	return nil, false, isIpv6
}

func GetGatewayIndex() uint32 {
	table, err := NewRouteTable()
	if err != nil {
		return 0
	}
	defer table.Close()
	rows, err := table.Routes()
	if err != nil {
		return 0
	}
	var minMetric uint32 = 0
	var ifIndex uint32 = 0
	var forwardMask uint32 = 0
	for _, row := range rows {
		if Inet_ntoa(row.ForwardDest, false) == "0.0.0.0" {
			if minMetric == 0 {
				minMetric = row.ForwardMetric1
				ifIndex = row.ForwardIfIndex
			} else {
				if row.ForwardMetric1 < minMetric || row.ForwardMask > forwardMask {
					minMetric = row.ForwardMetric1
					ifIndex = row.ForwardIfIndex
				}
			}
		}
	}
	return ifIndex
}

type NetworkAdapter struct {
	DNSServerSearchOrder []string
	DefaultIPGateway     []string
	IPAddress            []string
	Caption              string
	DHCPEnabled          bool
	InterfaceIndex       uint32
	ServiceName          string
	IPSubnet             []string
	SettingID            string
}

func GetNetworkAdapter() ([]NetworkAdapter, error) {
	var s = []NetworkAdapter{}
	err := wmi.Query("SELECT Caption,SettingID,InterfaceIndex,DNSServerSearchOrder,DefaultIPGateway,ServiceName,IPAddress,IPSubnet,DHCPEnabled       FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True", &s) // WHERE (BIOSVersion IS NOT NULL)
	if err != nil {
		log.Printf("err:%v\r\n", err)
		return nil, err
	}
	return s, nil
}
func SetNetConf(dnsIpv4 string, dnsIpv6 string) {

}

func ResetNetConf(ip string) {

}

func CmdHide(name string, arg ...string) *exec.Cmd {
	cmd := exec.Command(name, arg...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
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

func GetLocalAddresses() ([]lAddr, error) {
	lAddrs := []lAddr{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	aList, err := getAdapterList()
	if err != nil {
		return nil, err
	}

	for _, ifi := range ifaces {
		for ai := aList; ai != nil; ai = ai.Next {
			index := ai.Index
			if ifi.Index == int(index) {
				ipl := &ai.IpAddressList
				gwl := &ai.GatewayList
				for ; ipl != nil; ipl = ipl.Next {
					itemAddr := lAddr{}
					itemAddr.Name = ifi.Name
					itemAddr.IpAddress = fmt.Sprintf("%s", ipl.IpAddress.String)
					itemAddr.IpMask = fmt.Sprintf("%s", ipl.IpMask.String)
					itemAddr.GateWay = fmt.Sprintf("%s", gwl.IpAddress.String)
					lAddrs = append(lAddrs, itemAddr)
				}
			}
		}
	}
	return lAddrs, err
}
