package main

import "github.com/dosgo/goSocksTap/socksTap"

func main() {
	socksTap := socksTap.NewSocksTap(1095, "", 0)
	socksTap.Start()
	select {}
}
