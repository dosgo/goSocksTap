package main

import (
	"goSocksTap/socksTap"
)



func main(){

	var _socksTap= socksTap.SocksTap{};
	_socksTap.Start("127.0.0.1:10808","",true)

	select {

	}
}