//go:build windows
// +build windows

package forward

import (
	"sync"

	"github.com/dosgo/goSocksTap/comm/udpProxy"
	"github.com/dosgo/goSocksTap/winDivert"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	winDivert.CollectDNSRecords(dnsRecords)
}

func RedirectAllTCP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map) {
	winDivert.RedirectAllTCP(proxyPort, excludePorts, originalPorts)
}

func RedirectAllUDP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map, udpNat *udpProxy.UdpNat) {
	winDivert.RedirectAllUDP(proxyPort, excludePorts, originalPorts, udpNat)
}

func CloseWinDivert() {
	winDivert.CloseWinDivert()
}
func ForceRestartWithGID(pid int) (int, error) {
	return 0, nil
}
