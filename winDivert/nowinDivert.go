//go:build !windows
// +build !windows

package winDivert

/*only windows*/
func RedirectDNS(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {

}

/*only windows*/
func RedirectDNSV2(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {

}

/*only windows*/
func CloseWinDivert() {

}
