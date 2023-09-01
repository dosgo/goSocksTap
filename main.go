package main

import (
	"goSocksTap/socksTap"
)

func main() {

	var _socksTap = socksTap.SocksTap{}
	_socksTap.Start("192.168.7.134:10808", "", true, true)
	select {}
}
