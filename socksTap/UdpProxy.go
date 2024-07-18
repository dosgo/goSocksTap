package socksTap

import (
	"log"
	"net"
	"sync"

	"github.com/dosgo/go-tun2socks/core"
)

type UdpProxy struct {
	LocalAddr string
	Mapping   sync.Map
	Listener  *net.UDPConn
}

func NewUdpProxy(_localAddr string) *UdpProxy {
	return &UdpProxy{LocalAddr: _localAddr}
}

func (udpProxy *UdpProxy) Start() error {
	udpAddr, err := net.ResolveUDPAddr("udp", udpProxy.LocalAddr)
	if err != nil {
		return err
	}
	udpProxy.Listener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	buffer := make([]byte, 2048)
	for {
		n, sourceAddr, err := udpProxy.Listener.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading from UDP connection:", err)
			continue
		}

		destinationAddr, exists := udpProxy.Mapping.Load(sourceAddr.String())
		if !exists {
			log.Println("No mapping found for source address:", sourceAddr)
			continue
		}
		destinationAddr.(core.CommUDPConn).Write(buffer[:n])
	}
	return nil
}

func (udpProxy *UdpProxy) SendRemote(remoteAddr string, buffer []byte, conn core.CommUDPConn) error {
	udpProxy.Mapping.Store(remoteAddr, conn)
	destinationUdpAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return err
	}
	udpProxy.Listener.WriteToUDP(buffer, destinationUdpAddr)
	return nil
}

func (udpProxy *UdpProxy) RemoveAddr(remoteAddr string) error {
	udpProxy.Mapping.Delete(remoteAddr)
	return nil
}
