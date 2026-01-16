package main

import "github.com/dosgo/goSocksTap/socksTap"

func main() {
	socksTap := socksTap.NewSocksTap(1099, "127.0.0.1:10808", false)
	socksTap.Start()
	select {}
}
