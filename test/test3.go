package main

import "github.com/dosgo/goSocksTap/socksTap"

func main() {
	socksTap := socksTap.NewSocksTap(1099, "", 0)
	socksTap.Start()
	select {}
}
