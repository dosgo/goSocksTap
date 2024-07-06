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

var winDivert *divert.Handle
var winDivertRun = false

var winDivertEvent *divert.Handle
var winDivertEventRun = false

// 不处理的地址包括udp+tcp
var excludeOriginalAddr sync.Map
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
func RedirectDNS(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var filter = "outbound and !loopback and !impostor and udp.DstPort=53  and (udp.SrcPort>" + strconv.Itoa(sendEndPort) + " or udp.SrcPort<" + strconv.Itoa(sendStartPort) + ")"

	winDivert, err = divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	var recvBuf []byte = make([]byte, 1500)
	addr := divert.Address{}
	var recvLen uint
	for winDivertRun {
		if winDivert == nil {
			continue
		}
		recvLen, err = winDivert.Recv(recvBuf, &addr)
		if err != nil {
			log.Println(1, err)
			continue
		}
		sendDns(dnsAddr, _port, recvBuf, recvLen, &addr, "111")
	}
}

/*windows转发*/
func RedirectDNSV1(dnsAddr string, _port string) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var filter = "outbound and !loopback and !impostor and udp.DstPort=53"

	winDivert, err = divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}

	var recvBuf []byte = make([]byte, 1500)
	addr := divert.Address{}

	var recvLen uint

	for winDivertRun {
		if winDivert == nil {
			continue
		}
		recvLen, err = winDivert.Recv(recvBuf, &addr)
		if err != nil {
			log.Println(1, err)
			continue
		}
		var ipheadlen int
		ipv6 := recvBuf[0]>>4 == 6
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(recvBuf[0]&0xF) * 4
		}

		//如果是本机的请求直接发送
		srcPort := binary.BigEndian.Uint16(recvBuf[ipheadlen : ipheadlen+2])
		_, ok := excludeOriginalAddr.Load("udp:" + strconv.Itoa(int(srcPort)))
		if ok {
			winDivert.Send(recvBuf[:recvLen], &addr)
			continue
		}

		hash := fmt.Sprintf("%x", recvBuf[22:recvLen])
		_, ok = removeRepeat.Load(hash)
		if !ok {
			removeRepeat.Store(hash, 1)
			go sendDns(dnsAddr, _port, recvBuf, recvLen, &addr, hash)
		} else {
			fmt.Printf("dddd\r\n")
		}
		time.Sleep(time.Millisecond * 10)
	}

}

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
	winDivert, err = divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	var recvBuf []byte = make([]byte, 1500)
	addr := divert.Address{}
	var recvLen uint
	var ipHeadLen int
	for winDivertRun {
		if winDivert == nil {
			continue
		}
		recvLen, err = winDivert.Recv(recvBuf, &addr)
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
		/*
			_, ok := removeRepeat.Load(hash)
			if !ok {
				removeRepeat.Store(hash, int64(time.Now().Unix()))
				go sendDns(dnsAddr, _port, recvBuf, recvLen, &addr, hash)
			} else {
				fmt.Printf("udp pack fiter\r\n")
			}
		*/
		go sendDns(dnsAddr, _port, recvBuf, recvLen, &addr, hash)
		time.Sleep(time.Millisecond * 10)
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
		_, err = winDivert.Send(rawbuf[:ipHeadLen+int(udpHeader.Length)], addr)
		if err != nil {
			log.Println(1, err)
			return
		}
	}
}

/*网络事件监听*/
func NetEvent(pid string, ownPid bool) {

	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertEventRun = true
	var filter = "outbound"
	if ownPid {
		filter = filter + " and (processId=" + pid + " or  processId=" + strconv.Itoa(os.Getpid()) + ")"
	} else {
		filter = filter + " and processId=" + pid
	}
	winDivertEvent, err = divert.Open(filter, divert.LayerSocket, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}

	var recvBuf []byte = make([]byte, 1)
	addr := divert.Address{}
	for winDivertEventRun {
		if winDivertEvent == nil {
			continue
		}
		_, err = winDivertEvent.Recv(recvBuf, &addr)

		switch addr.Event() {
		case divert.EventSocketBind:
			if addr.Socket().Protocol == 17 {
				//udp只有53的才记录
				log.Printf("udp pid:%d  local Port:%d rport:%d\r\n", addr.Socket().ProcessID, addr.Socket().LocalPort, addr.Socket().RemotePort)
				excludeOriginalAddr.Store("udp:"+strconv.Itoa(int(addr.Socket().LocalPort)), int64(time.Now().Unix()))

			} else {
				excludeOriginalAddr.Store("tcp:"+strconv.Itoa(int(addr.Socket().LocalPort)), int64(time.Now().Unix()))
			}
			break
		case divert.EventSocketClose:
			if addr.Socket().Protocol == 17 {
				//log.Printf("udp close pid:%d  local Port:%d rport:%d\r\n", addr.Socket().ProcessID, addr.Socket().LocalPort, addr.Socket().RemotePort)
			}
			break
		}
	}

}

/*网络事件监听*/
func NetEventv1(pid string, ownPid bool) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertEventRun = true
	var filter = "outbound"
	if ownPid {
		filter = filter + " and (processId=" + pid + " or  processId=" + strconv.Itoa(os.Getpid()) + ")"
	} else {
		filter = filter + " and processId=" + pid
	}
	winDivertEvent, err = divert.Open(filter, divert.LayerFlow, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}

	var recvBuf []byte = make([]byte, 1)
	addr := divert.Address{}
	for winDivertEventRun {
		if winDivertEvent == nil {
			continue
		}
		_, err = winDivertEvent.Recv(recvBuf, &addr)

		switch addr.Event() {
		case divert.EventFlowEstablished:
			if addr.Socket().Protocol == 17 {
				//udp只有53的才记录
				if addr.Socket().RemotePort == 53 {
					log.Printf("udp pid:%d  local Port:%d rport:%d\r\n", addr.Socket().ProcessID, addr.Socket().LocalPort, addr.Socket().RemotePort)

					excludeOriginalAddr.Store("udp:"+strconv.Itoa(int(addr.Socket().LocalPort)), int64(time.Now().Unix()))
				}
			} else {
				excludeOriginalAddr.Store("tcp:"+strconv.Itoa(int(addr.Socket().LocalPort)), int64(time.Now().Unix()))
			}
			break
		case divert.EventFlowDeleted:
			if addr.Socket().Protocol == 17 {
				//log.Printf("udp close pid:%d  local Port:%d rport:%d\r\n", addr.Socket().ProcessID, addr.Socket().LocalPort, addr.Socket().RemotePort)
			}
			break
		}
	}

}

func CloseWinDivert() {
	winDivertRun = false
	if winDivert != nil {
		winDivert.Close()
	}

	winDivertEventRun = false
	if winDivertEvent != nil {
		winDivertEvent.Close()
	}
}
