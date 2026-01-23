package main

import "github.com/dosgo/goSocksTap/socksTap"

func main() {
	socksTap := socksTap.NewSocksTap(1095, "socks5://127.0.0.1:10801", 1)
	socksTap.Start()
	defer socksTap.Close()
	select {}
}
