//go:build !windows && !wasm
// +build !windows,!wasm

package netstat

import (
	"net/url"
	"strconv"

	"github.com/cakturk/go-netstat/netstat"
)

/*为啥要用这方法,因为Process在一些电脑比较耗时间只有匹配的才获取*/
func PortGetPid(laddr string) (int, error) {
	u, err := url.Parse(laddr)
	lPort, err := strconv.Atoi(u.Port())

	if err != nil {
		return 0, err
	}
	// get only listening TCP sockets
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen && s.LocalAddr.Port == uint16(lPort)
	})
	if err != nil {
		return 0, err
	}
	for _, ent := range tabs {
		if ent.Process != nil {
			return ent.Process.Pid, nil
		}
	}
	tabs, err = netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen && s.LocalAddr.Port == uint16(lPort)
	})
	if err != nil {
		return 0, err
	}
	for _, ent := range tabs {
		if ent.Process != nil {
			return ent.Process.Pid, nil
		}
	}
	return 0, err
}

func IsSocksServerAddr(pid int, addr string) bool {
	return false
}
func GetTcpBindList(pid int, slefPid bool) ([]uint16, error) {
	var ports []uint16
	return ports, nil
}
