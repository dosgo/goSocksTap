package comm

import (
	"log"

	"golang.org/x/time/rate"

	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type UdpLimit struct {
	Limit   *rate.Limiter
	Expired int64
}

var poolNatBuf = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

type CommConn interface {
	SetDeadline(t time.Time) error
	io.ReadWriteCloser
}

type TimeoutConn struct {
	Conn    CommConn
	TimeOut time.Duration
}

func (conn TimeoutConn) Read(buf []byte) (int, error) {
	conn.Conn.SetDeadline(time.Now().Add(conn.TimeOut))
	return conn.Conn.Read(buf)
}

func (conn TimeoutConn) Write(buf []byte) (int, error) {
	conn.Conn.SetDeadline(time.Now().Add(conn.TimeOut))
	return conn.Conn.Write(buf)
}

/*tcp swap*/
func TcpPipe(src CommConn, dst CommConn, duration time.Duration) {
	defer src.Close()
	defer dst.Close()
	srcT := TimeoutConn{src, duration}
	dstT := TimeoutConn{dst, duration}
	go io.Copy(srcT, dstT)
	io.Copy(dstT, srcT)
}

/*
get Unused B
return tunaddr tungw
*/
func GetUnusedTunAddr() (string, string) {
	laddrs, err := GetNetworkInfo()
	if err != nil {
		return "", ""
	}
	var laddrInfo = ""
	for _, _laddr := range laddrs {
		laddrInfo = laddrInfo + "net:" + _laddr.IpAddress
	}
	//tunAddr string,tunMask string,tunGW
	for i := 19; i < 254; i++ {
		if strings.Index(laddrInfo, "net:172."+strconv.Itoa(i)) == -1 {
			return "172." + strconv.Itoa(i) + ".0.2", "172." + strconv.Itoa(i) + ".0.1"
		}
	}
	return "", ""
}

func GetNetworkInfo() ([]lAddr, error) {
	intf, err := net.Interfaces()
	lAddrs := []lAddr{}
	if err != nil {
		log.Fatal("get network info failed: %v", err)
		return nil, err
	}
	for _, v := range intf {
		ips, err := v.Addrs()
		if err != nil {
			log.Fatal("get network addr failed: %v", err)
			return nil, err
		}
		//此处过滤loopback（本地回环）和isatap（isatap隧道）
		if !strings.Contains(v.Name, "Loopback") && !strings.Contains(v.Name, "isatap") {
			itemAddr := lAddr{}
			itemAddr.Name = v.Name
			itemAddr.MACAddress = v.HardwareAddr.String()
			for _, ip := range ips {
				if strings.Contains(ip.String(), ".") {
					_, ipNet, err1 := net.ParseCIDR(ip.String())
					if err1 == nil {
						itemAddr.IpAddress = ipNet.IP.String()
						itemAddr.IpMask = net.IP(ipNet.Mask).String()
					}
				}
			}
			lAddrs = append(lAddrs, itemAddr)
		}
	}
	return lAddrs, nil
}

func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if !ip.IsPrivate() {
		return true
	}
	return false
}

func AddRoute(tunAddr string, tunGw string, tunMask string) error {
	var netNat = make([]string, 4)
	//masks:=strings.Split(tunMask,".")
	masks := net.ParseIP(tunMask).To4()
	Addrs := strings.Split(tunAddr, ".")
	for i := 0; i <= 3; i++ {
		if masks[i] == 255 {
			netNat[i] = Addrs[i]
		} else {
			netNat[i] = "0"
		}
	}
	maskAddr := net.IPNet{IP: net.ParseIP(tunAddr), Mask: net.IPv4Mask(masks[0], masks[1], masks[2], masks[3])}
	maskAddrs := strings.Split(maskAddr.String(), "/")
	lAdds, err := GetLocalAddresses()
	var iName = ""
	if err == nil {
		for _, v := range lAdds {
			if strings.Index(v.IpAddress, tunAddr) != -1 {
				iName = v.Name
				break
			}
		}
	}

	//clear old
	CmdHide("route", "delete", strings.Join(netNat, ".")).Output()
	cmd := CmdHide("netsh", "interface", "ipv4", "add", "route", strings.Join(netNat, ".")+"/"+maskAddrs[1], iName, tunGw, "metric=6", "store=active")
	cmd.Run()
	CmdHide("ipconfig", "/flushdns").Run()
	return nil
}

type lAddr struct {
	Name       string
	IpAddress  string
	IpMask     string
	GateWay    string
	MACAddress string
}
