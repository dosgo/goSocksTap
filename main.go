package main

import (
	"flag"
	"log"

	"github.com/dosgo/goSocksTap/socksTap"
)

func main() {
	var sock5Addr = ""
	flag.StringVar(&sock5Addr, "sock5Addr", "127.0.0.1:10808", " socks5 addr ")
	var udpProxy = false
	flag.BoolVar(&udpProxy, "udpProxy", true, "use udpProxy ")
	flag.Parse()
	var _socksTap = socksTap.NewSocksTap(1080, sock5Addr, false)
	log.Printf("sock5Addr:%s\r\n", sock5Addr)
	log.Printf("udpProxy:%v\r\n", udpProxy)
	_socksTap.Start()
	select {}
}
