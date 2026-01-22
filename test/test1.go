package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/dosgo/goSocksTap/forward"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

func main() {
	dnsRecords := expirable.NewLRU[string, string](10000, nil, time.Minute*5)

	go forward.CollectDNSRecords(dnsRecords)
	var excludePorts sync.Map
	forward.NetEvent(os.Getpid(), &excludePorts)
	pid, _ := netstat.PortGetPid("127.0.0.1:10801")
	fmt.Printf("pid:%d\r\n", pid)
	select {}
}
