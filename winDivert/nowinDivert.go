//go:build !windows
// +build !windows

package winDivert

import "github.com/dosgo/goSocksTap/tunDns"

/*only windows*/
func RedirectDNS(dnsAddr string, dnsPort uint16, sendStartPort int, sendEndPort int, localHost bool) {

}

/*only windows*/
func RedirectDNSV2(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {

}

/*only windows*/
func CloseWinDivert() {

}

func NetEvent(pid uint32, tunDns *tunDns.TunDns) {

}
func HackDNSData(tunDns *tunDns.TunDns) {

}
func CloseNetEvent() {

}
