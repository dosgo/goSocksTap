//go:build windows
// +build windows

package forward

import (
	"sync"

	"github.com/dosgo/goSocksTap/winDivert"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	winDivert.CollectDNSRecords(dnsRecords)
}

func NetEvent(pid int, excludePorts *sync.Map) {
	winDivert.NetEvent(pid, excludePorts)
}

var mark int = 0x1aa

func RedirectAllTCP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map) {
	winDivert.RedirectAllTCP(proxyPort, excludePorts, originalPorts)
}

func CloseNetEvent() {
	winDivert.CloseNetEvent()
}

func CloseWinDivert() {
	winDivert.CloseWinDivert()
}
