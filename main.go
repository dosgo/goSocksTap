package main

import (
	_ "goSocksTap/socksTap"
	"strconv"
	"strings"
	"time"
)
import "fmt"
import "github.com/cakturk/go-netstat/netstat"

func main(){
	/*
	var _socksTap= socksTap.SocksTap{};
	_socksTap.Start("127.0.0.1:10808","sgd01-izoq.cgnodes.cloud")
	select {

	}*/
	t1 := time.Now() // get current time
	getdd("127.0.0.1:10808");
	elapsed := time.Since(t1)
	fmt.Println("App elapsed: ", elapsed)
}


func getdd(lSocks string)error{
	socksAddrs:=strings.Split(lSocks,":")
	lPort, err := strconv.Atoi(socksAddrs[1])
	var serverPid=0;
	// get only listening TCP sockets
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen && s.LocalAddr.Port==uint16(lPort)
	})

	if err != nil {
		return err
	}
	if len(tabs)>0 {
		serverPid=tabs[0].Process.Pid;
	}


	// UDP sockets
	socks, err := netstat.UDPSocks(func(s *netstat.SockTabEntry) bool {
		return s.Process.Pid==serverPid
	})
	if err != nil {
		return err
	}
	for _, e := range socks {
		fmt.Printf("LocalAddr:%s State:%s\n", e.LocalAddr, e.State)
	}
	return nil;
}