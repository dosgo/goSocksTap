package main

import (
	"goSocksTap/comm/netstat"
	"goSocksTap/socksTap"
	_ "goSocksTap/socksTap"
	"time"
)



func main(){

	var _socksTap= socksTap.SocksTap{};
	_socksTap.Start("127.0.0.1:10808","sgd01-izoq.cgnodes.cloud")
	pid,_:=netstat.PortGetPid("127.0.0.1:10808");

	for{
		netstat.GetTcpAddrByPid(pid)
		time.Sleep(time.Second*30);
	}
}