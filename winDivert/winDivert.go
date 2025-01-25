//go:build windows
// +build windows

package winDivert

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/imgk/divert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var outboundDivert *divert.Handle
var inboundDivert *divert.Handle
var eventDivert *divert.Handle
var winDivertRun = false

var divertDll = "WinDivert.dll"
var divertSys = "WinDivert32.sys"

// dns白名单
var dnsWhitelist sync.Map

type UDPHeader struct {
	SrcPort uint16
	DstPort uint16
	Length  uint16
	Check   uint16
}

func (h *UDPHeader) Marshal() ([]byte, error) {
	b := make([]byte, 8)
	//写入udp头
	binary.BigEndian.PutUint16(b[:], h.SrcPort)
	binary.BigEndian.PutUint16(b[2:], h.DstPort)
	binary.BigEndian.PutUint16(b[4:], h.Length)
	return b, nil
}
func (h *UDPHeader) Reset() {
	*h = UDPHeader{}
}

func (h *UDPHeader) Parse(b []byte) error {
	if len(b) < 8 {
		return nil
	}
	h.SrcPort = binary.BigEndian.Uint16(b[:2])
	h.DstPort = binary.BigEndian.Uint16(b[2:4])
	h.Length = binary.BigEndian.Uint16(b[4:6])
	h.Check = binary.BigEndian.Uint16(b[6:])
	return nil
}

func dllInit(_divertDll string) {
	_, err := os.Stat(_divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", _divertDll)
	}
}

type ForwardInfo struct {
	Src               net.IP
	Dst               net.IP
	InterfaceIndex    uint32
	SubInterfaceIndex uint32
	LastTime          int64
}

func RedirectDNS(dnsAddr string, dnsPort uint16, sendStartPort int, sendEndPort int, localHost bool) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var forward sync.Map
	// 启动清理过期项的 goroutine
	go func() {
		for winDivertRun {
			forward.Range(func(key, value interface{}) bool {
				expireableVal, ok := value.(ForwardInfo)
				if ok && expireableVal.LastTime+120 < time.Now().Unix() {
					// 直接删除过期的键
					forward.Delete(key)
				}
				return true
			})
			time.Sleep(time.Second * 120)
		}
	}()

	var filterIn = ""
	if dnsPort != 53 {
		filterIn = fmt.Sprintf("!impostor and udp.SrcPort=%d and ip.SrcAddr=%s", dnsPort, dnsAddr)
	} else {
		filterIn = fmt.Sprintf("!impostor and udp.SrcPort=53 and ip.SrcAddr=%s", dnsAddr)
	}
	inboundDivert, err := divert.Open(filterIn, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer inboundDivert.Close()

	recvBuf := make([]byte, 2024)
	addr := divert.Address{}

	// 出站重定向循环
	go func() {
		inboundUdpHeader := &UDPHeader{}
		// 出站重定向
		filterOut := "outbound  and !impostor and udp.DstPort=53 and ip.DstAddr!=" + dnsAddr + " and (udp.SrcPort>" + strconv.Itoa(sendEndPort) + " or udp.SrcPort<" + strconv.Itoa(sendStartPort) + ")"
		outboundDivert, err = divert.Open(filterOut, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			log.Printf("winDivert open failed: %v\r\n", err)
			return
		}
		defer outboundDivert.Close()

		for winDivertRun {
			recvLen, err := outboundDivert.Recv(recvBuf, &addr)
			if err != nil {
				log.Printf("winDivert recv failed: %v\r\n", err)
				return
			}
			isIpv6 := recvBuf[0]>>4 == 6
			ipHeadLen := 40 // Assuming IPv6 if not modified later
			if !isIpv6 {
				ipHeadLen = int(recvBuf[0]&0xF) * 4
			}

			inboundUdpHeader.Reset()
			inboundUdpHeader.Parse(recvBuf[ipHeadLen:])

			if isIpv6 {
				ipHeader, _ := ipv6.ParseHeader(recvBuf[:recvLen])
				forward.Store(inboundUdpHeader.SrcPort, ForwardInfo{Dst: ipHeader.Dst, Src: ipHeader.Src, LastTime: time.Now().Unix(), InterfaceIndex: addr.Network().InterfaceIndex, SubInterfaceIndex: addr.Network().SubInterfaceIndex})

			} else {
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])

				//	fmt.Printf("outbound src:%s dst:%s SrcPort:%d dnsAddr:%s\r\n", ipHeader.Src, ipHeader.Dst, udpHeader.SrcPort, dnsAddr)
				forward.Store(inboundUdpHeader.SrcPort, ForwardInfo{Dst: ipHeader.Dst, Src: ipHeader.Src, LastTime: time.Now().Unix(), InterfaceIndex: addr.Network().InterfaceIndex, SubInterfaceIndex: addr.Network().SubInterfaceIndex})
				ipHeader.Dst = net.ParseIP(dnsAddr)
				if localHost {
					ipHeader.Src = net.ParseIP(dnsAddr)
				}
				tempBuf, _ := ipHeader.Marshal()
				copy(recvBuf, tempBuf)

			}

			if dnsPort != 53 {
				inboundUdpHeader.DstPort = dnsPort
				tempBuf1, _ := inboundUdpHeader.Marshal()
				copy(recvBuf[ipHeadLen:], tempBuf1)
			}
			if localHost {
				addr.Network().InterfaceIndex = 1
				addr.Network().SubInterfaceIndex = 0
				addr.Flags |= uint8(0x01 << 2) //lookback=1
			}

			divert.CalcChecksums(recvBuf[:recvLen], &addr, 0)
			outboundDivert.Send(recvBuf[:recvLen], &addr)
		}
	}()

	// 入站重定向循环
	inboundBuf := make([]byte, 2024)
	inboundAddr := divert.Address{}
	inboundUdpHeader := &UDPHeader{}
	for winDivertRun {
		recvLen, err := inboundDivert.Recv(inboundBuf, &inboundAddr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}

		isIpv6 := inboundBuf[0]>>4 == 6
		ipHeadLen := 40 // Assuming IPv6 if not modified later
		if !isIpv6 {
			ipHeadLen = int(inboundBuf[0]&0xF) * 4
		}
		inboundUdpHeader.Reset()
		inboundUdpHeader.Parse(inboundBuf[ipHeadLen:])
		tempForward, ok := forward.Load(inboundUdpHeader.DstPort)
		forwardInfo := tempForward.(ForwardInfo)
		if isIpv6 {
			ipHeader, _ := ipv6.ParseHeader(inboundBuf[:recvLen])
			if ok {
				ipHeader.Src = forwardInfo.Dst
			}
		} else {
			ipHeader, _ := ipv4.ParseHeader(inboundBuf[:recvLen])
			if ok {
				ipHeader.Src = forwardInfo.Dst
				if localHost {
					ipHeader.Dst = forwardInfo.Src
				}
			}
			tempBuf, _ := ipHeader.Marshal()
			copy(inboundBuf, tempBuf)
		}
		if dnsPort != 53 {
			inboundUdpHeader.SrcPort = 53
			tempBuf1, _ := inboundUdpHeader.Marshal()
			copy(inboundBuf[ipHeadLen:], tempBuf1)
		}

		if localHost {
			inboundAddr.Network().InterfaceIndex = forwardInfo.InterfaceIndex       //conn->if_idx;
			inboundAddr.Network().SubInterfaceIndex = forwardInfo.SubInterfaceIndex //conn->sub_if_idx;                           //Outbound=0
			inboundAddr.Flags &= ^uint8(0x01 << 2)                                  //Loopback=0
		}
		divert.CalcChecksums(inboundBuf[:recvLen], &inboundAddr, 0)
		inboundDivert.Send(inboundBuf[:recvLen], &inboundAddr)
	}
}

func RedirectDNSV1(dnsAddr string, dnsPort uint16, sendStartPort int, sendEndPort int, localHost bool) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var forward sync.Map
	// 启动清理过期项的 goroutine
	go func() {
		for winDivertRun {
			forward.Range(func(key, value interface{}) bool {
				expireableVal, ok := value.(ForwardInfo)
				if ok && expireableVal.LastTime+120 < time.Now().Unix() {
					// 直接删除过期的键
					forward.Delete(key)
				}
				return true
			})
			time.Sleep(time.Second * 120)
		}
	}()
	//监控本进程的端口用于过滤
	go NetEvent()

	var filterIn = ""
	if dnsPort != 53 {
		filterIn = fmt.Sprintf("!impostor and udp.SrcPort=%d and ip.SrcAddr=%s", dnsPort, dnsAddr)
	} else {
		filterIn = fmt.Sprintf("!impostor and udp.SrcPort=53 and ip.SrcAddr=%s", dnsAddr)
	}
	inboundDivert, err := divert.Open(filterIn, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer inboundDivert.Close()

	recvBuf := make([]byte, 2024)
	addr := divert.Address{}

	// 出站重定向循环
	go func() {
		inboundUdpHeader := &UDPHeader{}
		// 出站重定向
		filterOut := "outbound  and !impostor and udp.DstPort=53 and ip.DstAddr!=" + dnsAddr + " and (udp.SrcPort>" + strconv.Itoa(sendEndPort) + " or udp.SrcPort<" + strconv.Itoa(sendStartPort) + ")"
		outboundDivert, err = divert.Open(filterOut, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			log.Printf("winDivert open failed: %v\r\n", err)
			return
		}
		defer outboundDivert.Close()

		for winDivertRun {
			recvLen, err := outboundDivert.Recv(recvBuf, &addr)
			if err != nil {
				log.Printf("winDivert recv failed: %v\r\n", err)
				return
			}

			isIpv6 := recvBuf[0]>>4 == 6
			ipHeadLen := 40 // Assuming IPv6 if not modified later
			if !isIpv6 {
				ipHeadLen = int(recvBuf[0]&0xF) * 4
			}

			inboundUdpHeader.Reset()
			inboundUdpHeader.Parse(recvBuf[ipHeadLen:])

			//如果是特定的端口直接转发跳过不
			_, ok := dnsWhitelist.Load(inboundUdpHeader.SrcPort)
			if ok {
				outboundDivert.Send(recvBuf[:recvLen], &addr)
				continue
			}

			if isIpv6 {
				ipHeader, _ := ipv6.ParseHeader(recvBuf[:recvLen])
				forward.Store(inboundUdpHeader.SrcPort, ForwardInfo{Dst: ipHeader.Dst, Src: ipHeader.Src, LastTime: time.Now().Unix(), InterfaceIndex: addr.Network().InterfaceIndex, SubInterfaceIndex: addr.Network().SubInterfaceIndex})

			} else {
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])

				//	fmt.Printf("outbound src:%s dst:%s SrcPort:%d dnsAddr:%s\r\n", ipHeader.Src, ipHeader.Dst, udpHeader.SrcPort, dnsAddr)
				forward.Store(inboundUdpHeader.SrcPort, ForwardInfo{Dst: ipHeader.Dst, Src: ipHeader.Src, LastTime: time.Now().Unix(), InterfaceIndex: addr.Network().InterfaceIndex, SubInterfaceIndex: addr.Network().SubInterfaceIndex})
				ipHeader.Dst = net.ParseIP(dnsAddr)
				//如果是本地主机，源也要设置成本地
				if localHost {
					ipHeader.Src = net.ParseIP(dnsAddr)
				}
				tempBuf, _ := ipHeader.Marshal()
				copy(recvBuf, tempBuf)

			}

			if dnsPort != 53 {
				inboundUdpHeader.DstPort = dnsPort
				tempBuf1, _ := inboundUdpHeader.Marshal()
				copy(recvBuf[ipHeadLen:], tempBuf1)
			}
			//如果是本地主机必须设置这个否则发不出去
			if localHost {
				addr.Network().InterfaceIndex = 1
				addr.Network().SubInterfaceIndex = 0
				addr.Flags |= uint8(0x01 << 2) //lookback=1
			}

			divert.CalcChecksums(recvBuf[:recvLen], &addr, 0)
			outboundDivert.Send(recvBuf[:recvLen], &addr)
		}
	}()

	// 入站重定向循环
	inboundBuf := make([]byte, 2024)
	inboundAddr := divert.Address{}
	inboundUdpHeader := &UDPHeader{}
	for winDivertRun {
		recvLen, err := inboundDivert.Recv(inboundBuf, &inboundAddr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}

		isIpv6 := inboundBuf[0]>>4 == 6
		ipHeadLen := 40 // Assuming IPv6 if not modified later
		if !isIpv6 {
			ipHeadLen = int(inboundBuf[0]&0xF) * 4
		}
		inboundUdpHeader.Reset()
		inboundUdpHeader.Parse(inboundBuf[ipHeadLen:])
		tempForward, ok := forward.Load(inboundUdpHeader.DstPort)
		forwardInfo := tempForward.(ForwardInfo)
		if isIpv6 {
			ipHeader, _ := ipv6.ParseHeader(inboundBuf[:recvLen])
			if ok {
				ipHeader.Src = forwardInfo.Dst
			}
		} else {
			ipHeader, _ := ipv4.ParseHeader(inboundBuf[:recvLen])
			if ok {
				ipHeader.Src = forwardInfo.Dst
				//如果是本地主机，dst也要设置成之前的来源
				if localHost {
					ipHeader.Dst = forwardInfo.Src
				}
			}
			tempBuf, _ := ipHeader.Marshal()
			copy(inboundBuf, tempBuf)
		}
		if dnsPort != 53 {
			inboundUdpHeader.SrcPort = 53
			tempBuf1, _ := inboundUdpHeader.Marshal()
			copy(inboundBuf[ipHeadLen:], tempBuf1)
		}
		////如果是本地主机必须设置这个否则发不出去
		if localHost {
			inboundAddr.Network().InterfaceIndex = forwardInfo.InterfaceIndex       //conn->if_idx;
			inboundAddr.Network().SubInterfaceIndex = forwardInfo.SubInterfaceIndex //conn->sub_if_idx;                           //Outbound=0
			inboundAddr.Flags &= ^uint8(0x01 << 2)                                  //Loopback=0
		}
		divert.CalcChecksums(inboundBuf[:recvLen], &inboundAddr, 0)
		inboundDivert.Send(inboundBuf[:recvLen], &inboundAddr)
	}
}

func NetEvent() {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var filter = fmt.Sprintf("processId=%d and udp", os.Getpid())

	eventDivert, err := divert.Open(filter, divert.LayerFlow, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	//先清空
	dnsWhitelist.Range(func(key, value interface{}) bool {
		dnsWhitelist.Delete(key)
		return true
	})
	//udp事件监控
	inboundBuf := make([]byte, 2024)
	addr := divert.Address{}
	go func() {
		for winDivertRun {
			_, err := eventDivert.Recv(inboundBuf, &addr)
			if err != nil {
				log.Printf("winDivert recv failed: %v\r\n", err)
				return
			}
			switch addr.Event() {
			case divert.EventFlowEstablished:
				fmt.Printf("bind RemotePort:%d\r\n", addr.Flow().LocalPort)
				dnsWhitelist.Store(addr.Flow().LocalPort, time.Now().Unix())
			case divert.EventFlowDeleted:
				dnsWhitelist.Delete(addr.Flow().LocalPort)
				fmt.Printf("remove RemotePort:%d\r\n", addr.Flow().LocalPort)
			}
		}
	}()
	ports, err := netstat.GetUdpBindList(os.Getpid(), false)
	if err == nil {
		for _, binding := range ports {
			// 在这里可以添加其他操作
			dnsWhitelist.Store(binding, time.Now().Unix())
		}
	}
}

func CloseWinDivert() {
	winDivertRun = false
	if outboundDivert != nil {
		outboundDivert.Close()
	}
	if inboundDivert != nil {
		inboundDivert.Close()
	}
	if eventDivert != nil {
		eventDivert.Close()
	}
}
