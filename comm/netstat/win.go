//go:build windows
// +build windows

package netstat

import (
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/cakturk/go-netstat/netstat"
)

/*为啥要用这方法,因为Process在一些电脑比较耗时间只有匹配的才获取*/
func PortGetPid(laddr string) (int, error) {
	u, err := url.Parse(laddr)
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return 0, err
	}
	tbl, err := netstat.GetTCPTable2(true)
	if err != nil {
		return 0, err
	}
	s := tbl.Rows()
	for i := range s {
		ent := netstat.SockTabEntry{
			LocalAddr:  s[i].LocalSock(),
			RemoteAddr: s[i].RemoteSock(),
			State:      s[i].SockState(),
		}
		if ent.State == netstat.Listen && ent.LocalAddr.Port == uint16(port) {
			return int(s[i].WinPid), nil
		}
	}
	return 0, nil
}

func IsSocksServerAddr(pid int, addr string) bool {
	tbl, err := netstat.GetTCPTable2(true)
	if err != nil {
		return false
	}
	s := tbl.Rows()
	for i := range s {
		ent := netstat.SockTabEntry{
			LocalAddr:  s[i].LocalSock(),
			RemoteAddr: s[i].RemoteSock(),
			State:      s[i].SockState(),
		}
		if strings.Index(ent.LocalAddr.String(), addr) != -1 {
			if int(s[i].WinPid) == pid {
				return true
			}
		}
	}
	return false
}

func GetUdpBindList(pid int, slefPid bool) ([]uint16, error) {
	tbl, err := netstat.GetUDPTableOwnerPID(true)
	if err != nil {
		return nil, errors.New("error")
	}
	var _slefPid = os.Getpid()
	var ports []uint16
	s := tbl.Rows()
	for i := range s {
		if int(s[i].WinPid) == pid || int(s[i].WinPid) == _slefPid {
			ports = append(ports, s[i].LocalSock().Port)
		}
	}
	return ports, nil
}

func GetTcpBindList(pid int, slefPid bool) ([]uint16, error) {
	tbl, err := netstat.GetTCPTable2(true)
	if err != nil {
		return nil, errors.New("error")
	}
	var _slefPid = os.Getpid()
	var ports []uint16
	s := tbl.Rows()
	for i := range s {
		if int(s[i].WinPid) == pid || int(s[i].WinPid) == _slefPid {
			ports = append(ports, s[i].LocalSock().Port)
		}
	}
	return ports, nil
}
