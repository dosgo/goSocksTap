package main

import (
	"os"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/winDivert"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func main() {
	dnsRecords := expirable.NewLRU[string, string](10000, nil, time.Minute*5)

	go winDivert.CollectDNSRecords(dnsRecords)
	var excludePorts sync.Map
	winDivert.NetEvent(os.Getpid(), &excludePorts)
}
