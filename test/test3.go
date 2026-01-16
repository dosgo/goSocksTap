package main

import "github.com/dosgo/goSocksTap/socksTap"

func main() {
	socksTap := socksTap.NewSocksTap(1080, "", false)
	socksTap.Start()
	select {}
}
