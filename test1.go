package main

import (
	"github.com/dosgo/goSocksTap/winDivert"
)

func main() {
	go winDivert.CollectDNSRecords()
	winDivert.NetEventRecords()
}
