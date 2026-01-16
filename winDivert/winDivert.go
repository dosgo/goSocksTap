//go:build windows
// +build windows

package winDivert

import (
	_ "embed"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/dosgo/goSocksTap/tunDns"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/imgk/divert-go"
	"github.com/miekg/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var outboundDivert *divert.Handle
var inboundDivert *divert.Handle
var eventDivert *divert.Handle
var winDivertRun = false
var netEventRun = false

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

	inboundDivert, err = divert.Open(filterIn, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
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
		_, ok := tunDns.ExcludePorts.Load(inboundUdpHeader.DstPort)
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

	eventDivert, err = divert.Open(filter, divert.LayerFlow, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer eventDivert.Close()
	//先清空
	tunDns.ExcludePorts.Range(func(key, value interface{}) bool {
		tunDns.ExcludePorts.Delete(key)
		return true
	})
	//monitorDns(pid, tunDns)
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
			tunDns.ExcludePorts.Store(addr.Flow().LocalPort, time.Now().Unix())
		case divert.EventFlowDeleted:
			tunDns.ExcludePorts.Delete(addr.Flow().LocalPort)
		}
	}

}

var addrRecords = expirable.NewLRU[string, bool](10000, nil, time.Minute*5)

func NetEventRecords() {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	netEventRun = true
	var filter = fmt.Sprintf("!loopback")

	eventDivert, err := divert.Open(filter, divert.LayerSocket, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer inboundDivert.Close()

	//monitorDns(pid, tunDns)
	//udp事件监控
	inboundBuf := make([]byte, 2024)
	addr := divert.Address{}
	for netEventRun {
		_, err := eventDivert.Recv(inboundBuf, &addr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}

		var localIP netip.Addr
		var remoteIP netip.Addr

		flow := addr.Flow()
		if addr.Layer() == 1 || addr.Layer() == 5 {
			localIP = ParseIPFromUint8(flow.LocalAddress, true)
			remoteIP = ParseIPFromUint8(flow.RemoteAddress, true)
		} else {
			localIP = ParseIPFromUint8(flow.LocalAddress, false)

			remoteIP = ParseIPFromUint8(flow.RemoteAddress, false)
		}

		switch addr.Event() {
		case divert.EventSocketBind:
			//tunDns.ExcludePorts.Store(addr.Flow().LocalPort, time.Now().Unix())
			addrRecords.Add(remoteIP.String(), true)
			fmt.Printf("add addr %s %d  rddr:%s rport:%d pid:%d\r\n", localIP.String(), addr.Flow().LocalPort, remoteIP.String(), addr.Flow().RemotePort, flow.ProcessID)
		case divert.EventSocketClose:
			addrRecords.Remove(remoteIP.String())
			//fmt.Printf("remote addr %s %d \r\n", localIP.String(), addr.Flow().LocalPort)
			//tunDns.ExcludePorts.Delete(addr.Flow().LocalPort)
		}
	}
}

func ParseIPFromUint8(data [16]uint8, isIPv6 bool) netip.Addr {
	if isIPv6 {
		return netip.AddrFrom16(data)
	}
	// IPv4 转换：网络字节序是大端，直接读取前 4 字节
	// 如果你的数据在数组里是 [127, 0, 0, 1]，BigEndian.Uint32 会读成 0x7F000001
	// netip.AddrFrom4 会正确处理这种标准顺序
	return netip.AddrFrom4([4]byte{data[3], data[2], data[1], data[0]})
}

// CollectDNSRecords 拦截并解析所有 DNS 返回记录

var dnsCache = expirable.NewLRU[string, string](10000, nil, time.Minute*5)

func GetDomainByIP(ip string) (string, bool) {
	if info, ok := dnsCache.Get(ip); ok {
		return info, true
	}
	return "", false
}
func CollectDNSRecords() {
	// 过滤器：仅入站、来自 53 端口的 UDP 包
	// !impostor 确保不是我们自己注入的包
	filter := "inbound and !impostor and udp.SrcPort = 53"

	handle, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("WinDivert open failed: %v", err)
		return
	}
	defer handle.Close()

	inboundBuf := make([]byte, 2048)
	addr := divert.Address{}

	for {
		recvLen, err := handle.Recv(inboundBuf, &addr)
		if err != nil {
			continue
		}

		// 1. 定位 DNS Payload 位置
		ipHeadLen := 20 // 默认 IPv4
		if inboundBuf[0]>>4 == 6 {
			ipHeadLen = 40 // IPv6
		} else {
			ipHeadLen = int(inboundBuf[0]&0xF) * 4
		}

		// 8 字节是 UDP Header 长度
		dnsData := inboundBuf[ipHeadLen+8 : recvLen]

		// 2. 使用 miekg/dns 解码
		msg := new(dns.Msg)
		if err := msg.Unpack(dnsData); err != nil {
			continue
		}

		// 3. 提取 Answer 记录
		if msg.Response {
			for _, answer := range msg.Answer {
				// 获取域名
				name := answer.Header().Name

				// 根据记录类型提取 IP
				switch rr := answer.(type) {
				case *dns.A:
					dnsCache.Add(rr.A.String(), name)
					log.Printf("[DNS A] 域名: %s -> IP: %s", name, rr.A.String())
					// 这里可以执行你的 GeoIP 分流逻辑
				case *dns.AAAA:
					dnsCache.Add(rr.AAAA.String(), name)
					log.Printf("[DNS AAAA] 域名: %s -> IPv6: %s", name, rr.AAAA.String())
				}
			}
		}
	}
}

func CloseWinDivert() {
	winDivertRun = false
	netEventRun = false
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
		eventDivert = nil
	}
}
