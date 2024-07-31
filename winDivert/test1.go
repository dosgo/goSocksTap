package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/winDivert"
	"github.com/imgk/divert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func main() {
	RedirectDns("114.114.114.114")
	select {}
}

type ForwardInfo struct {
	Value    net.IP
	LastTime int64
}

func RedirectDns(toDst string) {
	var forward sync.Map
	// 启动清理过期项的 goroutine
	go func() {
		ticker := time.NewTicker(time.Minute * 1)
		defer ticker.Stop()
		for range ticker.C {
			forward.Range(func(key, value interface{}) bool {
				expireableVal, ok := value.(ForwardInfo)
				if ok && expireableVal.LastTime+120 < time.Now().Unix() {
					// 直接删除过期的键
					forward.Delete(key)
				}
				return true
			})
		}
	}()

	// 出站重定向
	filterOut := fmt.Sprintf("outbound and !loopback and !impostor and udp.DstPort=53 and ip.DstAddr!=%s", toDst)
	outbound, err := divert.Open(filterOut, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer outbound.Close()

	// 入站重定向
	filterIn := fmt.Sprintf("inbound and !loopback and !impostor and udp.SrcPort=53 and ip.SrcAddr=%s", toDst)
	inbound, err := divert.Open(filterIn, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer inbound.Close()

	recvBuf := make([]byte, 2024)
	addr := divert.Address{}

	// 出站重定向循环
	go func() {
		for {
			recvLen, err := outbound.Recv(recvBuf, &addr)
			if err != nil {
				log.Printf("winDivert recv failed: %v\r\n", err)
				return
			}
			isIpv6 := recvBuf[0]>>4 == 6
			ipHeadLen := 40 // Assuming IPv6 if not modified later
			if !isIpv6 {
				ipHeadLen = int(recvBuf[0]&0xF) * 4
			}

			udpHeader := &winDivert.UDPHeader{}
			udpHeader.Parse(recvBuf[ipHeadLen:])

			if isIpv6 {
				ipHeader, _ := ipv6.ParseHeader(recvBuf[:recvLen])
				forward.Store(udpHeader.SrcPort, ForwardInfo{Value: ipHeader.Dst, LastTime: time.Now().Unix()})

			} else {
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])
				forward.Store(udpHeader.SrcPort, ForwardInfo{Value: ipHeader.Dst, LastTime: time.Now().Unix()})
				ipHeader.Dst = net.ParseIP(toDst)
				tempBuf, _ := ipHeader.Marshal()
				copy(recvBuf, tempBuf)
			}

			divert.CalcChecksums(recvBuf[:recvLen], &addr, 0)
			outbound.Send(recvBuf[:recvLen], &addr)
		}
	}()

	// 入站重定向循环
	inboundBuf := make([]byte, 2024)
	for {
		recvLen, err := inbound.Recv(inboundBuf, &addr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}

		isIpv6 := inboundBuf[0]>>4 == 6
		ipHeadLen := 40 // Assuming IPv6 if not modified later
		if !isIpv6 {
			ipHeadLen = int(inboundBuf[0]&0xF) * 4
		}

		udpHeader := &winDivert.UDPHeader{}
		udpHeader.Parse(inboundBuf[ipHeadLen:])
		forwardInfo, ok := forward.Load(udpHeader.DstPort)

		if isIpv6 {
			ipHeader, _ := ipv6.ParseHeader(inboundBuf[:recvLen])
			if ok {
				ipHeader.Src = forwardInfo.(ForwardInfo).Value
			}
		} else {
			ipHeader, _ := ipv4.ParseHeader(inboundBuf[:recvLen])
			if ok {
				fmt.Printf("ddd\r\n")
				ipHeader.Src = forwardInfo.(ForwardInfo).Value
			}
			tempBuf, _ := ipHeader.Marshal()
			copy(inboundBuf, tempBuf)
		}
		divert.CalcChecksums(inboundBuf[:recvLen], &addr, 0)
		inbound.Send(inboundBuf[:recvLen], &addr)
	}
}
