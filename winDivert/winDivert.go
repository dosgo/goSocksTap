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

	"github.com/bi-zone/etw"
	"github.com/dosgo/goSocksTap/tunDns"
	"github.com/imgk/divert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/windows"
)

var outboundDivert *divert.Handle
var inboundDivert *divert.Handle
var eventDivert *divert.Handle
var winDivertRun = false
var netEventRun = false
var etwSession *etw.Session

var divertDll = "WinDivert.dll"
var divertSys = "WinDivert32.sys"

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

/*劫持dns数据*/
func HackDNSData(tunDns *tunDns.TunDns) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true

	//监控本进程的端口用于过滤
	var filterIn = ""
	filterIn = fmt.Sprintf("!impostor and udp.SrcPort=53")

	inboundDivert, err := divert.Open(filterIn, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer inboundDivert.Close()
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
		//如果是特定的端口直接转发跳过不
		_, ok := tunDns.ExcludePorts.Load(inboundUdpHeader.SrcPort)
		if !ok {
			newBuf, err := tunDns.ModifyDNSResponse(inboundBuf[ipHeadLen+8 : recvLen])
			if err == nil {
				copy(inboundBuf[ipHeadLen+8:], newBuf[:len(inboundBuf[ipHeadLen+8:recvLen])])
			}
		}
		divert.CalcChecksums(inboundBuf[:recvLen], &inboundAddr, 0)
		inboundDivert.Send(inboundBuf[:recvLen], &inboundAddr)
	}
}

func NetEvent(pid uint32, tunDns *tunDns.TunDns) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	netEventRun = true
	var filter = fmt.Sprintf("processId=%d or processId=%d and udp", os.Getpid(), pid)

	eventDivert, err := divert.Open(filter, divert.LayerFlow, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer inboundDivert.Close()
	//先清空
	tunDns.ExcludePorts.Range(func(key, value interface{}) bool {
		tunDns.ExcludePorts.Delete(key)
		return true
	})
	etwSession = monitorDns(pid, tunDns)
	//udp事件监控
	inboundBuf := make([]byte, 2024)
	addr := divert.Address{}
	for netEventRun {
		_, err := eventDivert.Recv(inboundBuf, &addr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}
		switch addr.Event() {
		case divert.EventFlowEstablished:
			fmt.Printf("bind RemotePort:%d\r\n", addr.Flow().LocalPort)
			tunDns.ExcludePorts.Store(addr.Flow().LocalPort, time.Now().Unix())
		case divert.EventFlowDeleted:
			tunDns.ExcludePorts.Delete(addr.Flow().LocalPort)
			fmt.Printf("remove RemotePort:%d\r\n", addr.Flow().LocalPort)
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

func CloseNetEvent() {
	netEventRun = false
	if eventDivert != nil {
		eventDivert.Close()
		eventDivert = nil
	}
	if etwSession != nil {
		etwSession.Close()
		etwSession = nil
	}
}

func monitorDns(pid uint32, tunDns *tunDns.TunDns) *etw.Session {
	// Subscribe to Microsoft-Windows-DNS-Client
	guid, _ := windows.GUIDFromString("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
	session, err := etw.NewSession(guid)
	if err != nil {
		return nil
	}
	// Wait for "DNS query request" events to log outgoing DNS requests.
	cb := func(e *etw.Event) {
		if e.Header.ID != 3006 {
			return
		}
		if e.Header.ProcessID != pid {
			return
		}
		if data, err := e.EventProperties(); err == nil && data["QueryType"] == "1" {
			tunDns.ExcludeDomains.Store(data["QueryName"].(string)+".", 1)
			log.Printf("PID %d just queried DNS for domain:%v", e.Header.ProcessID, data["QueryName"])
		}
	}

	if err := session.Process(cb); err != nil {
		log.Printf("[ERR] Got error processing events: %s", err)
	}
	return session
}
