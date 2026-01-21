package main

import "github.com/dosgo/goSocksTap/socksTap"

func main() {
	socksTap := socksTap.NewSocksTap(1095, "127.0.0.1:10801", 0)
	socksTap.Start()
	select {}
}
