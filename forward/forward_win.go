//go:build windows
// +build windows

package forward

import (
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/udpProxy"
	"github.com/dosgo/goSocksTap/winDivert"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	flushWithAPI()
	winDivert.CollectDNSRecords(dnsRecords)
}

func RedirectAllTCP(proxyPort uint16, excludePorts *comm.PortBitmap, originalPorts *sync.Map) {
	winDivert.RedirectAllTCP(proxyPort, excludePorts, originalPorts)
}

func RedirectAllUDP(proxyPort uint16, excludePorts *comm.PortBitmap, originalPorts *sync.Map, udpNat *udpProxy.UdpNat) {
	winDivert.RedirectAllUDP(proxyPort, excludePorts, originalPorts, udpNat)
}

func Stop() {
	winDivert.CloseWinDivert()
}
func ForceRestartWithGID(pid int) (int, error) {
	return 0, nil
}
func flushWithAPI() error {
	dnsapi := syscall.NewLazyDLL("dnsapi.dll")
	proc := dnsapi.NewProc("DnsFlushResolverCache")
	r1, _, err := proc.Call()
	if r1 == 0 {
		return fmt.Errorf("API call failed: %v", err)
	}
	return nil
}

func CheckUpdate(pid int, excludePorts *comm.PortBitmap) {
	winDivert.CloseNetEvent()
	time.Sleep(time.Millisecond * 2)
	go winDivert.NetEvent(pid, excludePorts)
}
