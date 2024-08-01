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

	"math/rand"

	"github.com/imgk/divert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var outboundDivert *divert.Handle
var winDivertRun = false

var inboundDivert *divert.Handle

// 不处理的地址包括udp+tcp
var divertDll = "WinDivert.dll"
var divertSys = "WinDivert32.sys"

var removeRepeat sync.Map

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

/*windows转发*/
/*windows转发*/
func RedirectDNSV2(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var filter = "outbound and !loopback and !impostor and udp.DstPort=53  and (udp.SrcPort>" + strconv.Itoa(sendEndPort) + " or udp.SrcPort<" + strconv.Itoa(sendStartPort) + ")"
	outboundDivert, err = divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	var recvBuf []byte = make([]byte, 1500)
	addr := divert.Address{}
	var recvLen uint
	var ipHeadLen int
	for winDivertRun {
		if outboundDivert == nil {
			continue
		}
		recvLen, err = outboundDivert.Recv(recvBuf, &addr)
		if err != nil {
			log.Println(1, err)
			continue
		}

		ipv6 := recvBuf[0]>>4 == 6
		if ipv6 {
			ipHeadLen = 40
		} else {
			ipHeadLen = int(recvBuf[0]&0xF) * 4
		}
		hash := fmt.Sprintf("%x", recvBuf[ipHeadLen+2:recvLen])
		go sendDns(dnsAddr, _port, recvBuf, recvLen, &addr, hash)
		time.Sleep(time.Millisecond * 10)
	}
}
func RedirectDNSTest(dnsAddr string, dnsPort uint16, sendStartPort int, sendEndPort int, localHost bool) {
	fmt.Printf("dnsAddr:%s_port:%d\r\n", dnsAddr, dnsPort)
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

			udpHeader := &UDPHeader{}
			udpHeader.Parse(recvBuf[ipHeadLen:])

			if isIpv6 {
				ipHeader, _ := ipv6.ParseHeader(recvBuf[:recvLen])
				forward.Store(udpHeader.SrcPort, ForwardInfo{Dst: ipHeader.Dst, Src: ipHeader.Src, LastTime: time.Now().Unix(), InterfaceIndex: addr.Network().InterfaceIndex, SubInterfaceIndex: addr.Network().SubInterfaceIndex})

			} else {
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])

				//	fmt.Printf("outbound src:%s dst:%s SrcPort:%d dnsAddr:%s\r\n", ipHeader.Src, ipHeader.Dst, udpHeader.SrcPort, dnsAddr)
				forward.Store(udpHeader.SrcPort, ForwardInfo{Dst: ipHeader.Dst, Src: ipHeader.Src, LastTime: time.Now().Unix(), InterfaceIndex: addr.Network().InterfaceIndex, SubInterfaceIndex: addr.Network().SubInterfaceIndex})
				ipHeader.Dst = net.ParseIP(dnsAddr)
				if localHost {
					ipHeader.Src = net.ParseIP(dnsAddr)
				}
				tempBuf, _ := ipHeader.Marshal()
				copy(recvBuf, tempBuf)

			}
			/*
				_portNum, _ := strconv.ParseInt(_port, 10, 16)
				udpHeader.DstPort = uint16(_portNum)
				tempBuf1, _ := udpHeader.Marshal()
				copy(recvBuf[ipHeadLen:], tempBuf1)
			*/
			if dnsPort != 53 {
				udpHeader.DstPort = dnsPort
				tempBuf1, _ := udpHeader.Marshal()
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
		fmt.Printf("inbound1\r\n")
		udpHeader := &UDPHeader{}
		udpHeader.Parse(inboundBuf[ipHeadLen:])
		tempForward, ok := forward.Load(udpHeader.DstPort)
		forwardInfo := tempForward.(ForwardInfo)
		if isIpv6 {
			ipHeader, _ := ipv6.ParseHeader(inboundBuf[:recvLen])
			if ok {
				ipHeader.Src = forwardInfo.Dst
			}
		} else {
			ipHeader, _ := ipv4.ParseHeader(inboundBuf[:recvLen])
			if ok {
				fmt.Printf("inbound\r\n")
				ipHeader.Src = forwardInfo.Dst
				if localHost {
					ipHeader.Dst = forwardInfo.Src
				}
			}
			tempBuf, _ := ipHeader.Marshal()
			copy(inboundBuf, tempBuf)
		}
		if dnsPort != 53 {
			udpHeader.SrcPort = 53
			tempBuf1, _ := udpHeader.Marshal()
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
func sendDns(dnsAddr string, port string, recvBuf []byte, recvLen uint, addr *divert.Address, hash string) {
	defer removeRepeat.Delete(hash)
	dnsConn, err := net.DialTimeout("udp", dnsAddr+":"+port, 15*time.Second)
	if err != nil {
		return
	}
	defer dnsConn.Close()

	isIpv6 := recvBuf[0]>>4 == 6
	ipHeadLen := 40 // Assuming IPv6 if not modified later
	if !isIpv6 {
		ipHeadLen = int(recvBuf[0]&0xF) * 4
	}

	// Create a buffer for the entire packet
	rawbuf := make([]byte, 1500)
	var dnsRecvBuf []byte = make([]byte, 1500)
	var udpHeadLen = 8
	dnsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	dnsConn.Write(recvBuf[ipHeadLen+udpHeadLen : recvLen])
	dnsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	conRecvLen, err := dnsConn.Read(dnsRecvBuf)
	if err == nil {

		srcUdpHeader := &UDPHeader{}
		srcUdpHeader.Parse(recvBuf[ipHeadLen:])

		// Define the UDP header
		udpHeader := &UDPHeader{}
		// Set UDP header fields
		udpHeader.SrcPort = srcUdpHeader.DstPort
		udpHeader.DstPort = srcUdpHeader.SrcPort
		udpHeader.Length = uint16(conRecvLen + udpHeadLen)

		// Set IP header fields based on IPv4 or IPv6
		if isIpv6 {
			srcHeader, err := ipv6.ParseHeader(recvBuf[:recvLen])
			if err != nil {
				return
			}

			ipHeader := &ipv6.Header{
				Version: ipv6.Version, // Or 6 for IPv6
			}
			//交换源跟目的地址
			ipHeader.Src = srcHeader.Dst // Assuming loopback address for example
			ipHeader.Dst = srcHeader.Src // Assuming localhost IPv6 for example
			ipHeader.PayloadLen = conRecvLen + udpHeadLen

			VersionTrafficClassFlowLabel := [4]byte{6 << 4, 0, 0, 0}
			copy(rawbuf[:4], VersionTrafficClassFlowLabel[:])
			binary.BigEndian.PutUint16(rawbuf[4:], uint16(ipHeader.PayloadLen))

			rawbuf[6] = 17  // NextHeader udp
			rawbuf[7] = 255 // Default Hop Limit
			//交换端口地址
			if ip := ipHeader.Src.To16(); ip != nil {
				copy(rawbuf[8:], ip[:net.IPv6len])
			}
			if ip := ipHeader.Dst.To16(); ip != nil {
				copy(rawbuf[24:], ip[:net.IPv6len])
			}

		} else {
			srcHeader, err := ipv4.ParseHeader(recvBuf[:recvLen])
			if err != nil {
				return
			}
			ipHeader := &ipv4.Header{
				Version:  ipv4.Version,     // Or 6 for IPv6
				Len:      ipv4.HeaderLen,   // For IPv4, assuming fixed header size
				TOS:      0,                // Traffic class or Type of Service
				TotalLen: 0,                // We'll calculate and set this later
				ID:       rand.Intn(65535), // Unique identifier for the packet
				FragOff:  0,                // Fragment offset
				TTL:      64,               // Time to live
				Protocol: 17,               // UDP protocol
			}
			//交换源跟目的地址
			ipHeader.Src = srcHeader.Dst
			ipHeader.Dst = srcHeader.Src

			//ip头包总大小
			ipHeader.TotalLen = ipHeadLen + int(udpHeader.Length)
			headBuf, _ := ipHeader.Marshal()
			//写入ip头
			copy(rawbuf[0:], headBuf)

		}

		//写入udp头
		udpHeadBuf, _ := udpHeader.Marshal()
		copy(rawbuf[ipHeadLen:], udpHeadBuf)

		// 写入udp数据
		copy(rawbuf[ipHeadLen+udpHeadLen:], dnsRecvBuf[:conRecvLen])

		divert.CalcChecksums(rawbuf[:ipHeadLen+int(udpHeader.Length)], addr, 0)
		_, err = outboundDivert.Send(rawbuf[:ipHeadLen+int(udpHeader.Length)], addr)
		if err != nil {
			log.Println(1, err)
			return
		}
	}
}

type ForwardInfo struct {
	Value    net.IP
	LastTime int64
}

func RedirectDNS(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {
	fmt.Printf("dnsAddr:%s_port:%d\r\n", dnsAddr, _port)
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

	// 出站重定向
	filterOut := "outbound  and !impostor and udp.DstPort=53 and ip.DstAddr!=" + dnsAddr + " and (udp.SrcPort>" + strconv.Itoa(sendEndPort) + " or udp.SrcPort<" + strconv.Itoa(sendStartPort) + ")"
	outboundDivert, err = divert.Open(filterOut, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer outboundDivert.Close()

	// 入站重定向
	filterIn := fmt.Sprintf("    udp.SrcPort=53 and ip.SrcAddr=%s", dnsAddr)
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

			udpHeader := &UDPHeader{}
			udpHeader.Parse(recvBuf[ipHeadLen:])

			if isIpv6 {
				ipHeader, _ := ipv6.ParseHeader(recvBuf[:recvLen])
				forward.Store(udpHeader.SrcPort, ForwardInfo{Value: ipHeader.Dst, LastTime: time.Now().Unix()})

			} else {
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])

				//	fmt.Printf("outbound src:%s dst:%s SrcPort:%d dnsAddr:%s\r\n", ipHeader.Src, ipHeader.Dst, udpHeader.SrcPort, dnsAddr)
				forward.Store(udpHeader.SrcPort, ForwardInfo{Value: ipHeader.Dst, LastTime: time.Now().Unix()})
				ipHeader.Dst = net.ParseIP(dnsAddr)
				tempBuf, _ := ipHeader.Marshal()
				copy(recvBuf, tempBuf)

			}
			/*
				_portNum, _ := strconv.ParseInt(_port, 10, 16)
				udpHeader.DstPort = uint16(_portNum)
				tempBuf1, _ := udpHeader.Marshal()
				copy(recvBuf[ipHeadLen:], tempBuf1)
			*/
			divert.CalcChecksums(recvBuf[:recvLen], &addr, 0)
			outboundDivert.Send(recvBuf[:recvLen], &addr)
		}
	}()

	// 入站重定向循环
	inboundBuf := make([]byte, 2024)
	for winDivertRun {
		recvLen, err := inboundDivert.Recv(inboundBuf, &addr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}

		isIpv6 := inboundBuf[0]>>4 == 6
		ipHeadLen := 40 // Assuming IPv6 if not modified later
		if !isIpv6 {
			ipHeadLen = int(inboundBuf[0]&0xF) * 4
		}
		fmt.Printf("inbound1\r\n")
		udpHeader := &UDPHeader{}
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
				fmt.Printf("inbound\r\n")
				ipHeader.Src = forwardInfo.(ForwardInfo).Value
			}
			tempBuf, _ := ipHeader.Marshal()
			copy(inboundBuf, tempBuf)
		}

		divert.CalcChecksums(inboundBuf[:recvLen], &addr, 0)
		inboundDivert.Send(inboundBuf[:recvLen], &addr)
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
}
