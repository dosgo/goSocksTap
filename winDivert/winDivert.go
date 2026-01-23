//go:build windows
// +build windows

package winDivert

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/dosgo/goSocksTap/comm"
	"github.com/dosgo/goSocksTap/comm/netstat"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/imgk/divert-go"
	"github.com/miekg/dns"
)

var dnsDivert *divert.Handle
var tcpDivert *divert.Handle
var eventDivert *divert.Handle

var divertDll = "WinDivert.dll"
var divertSys = "WinDivert32.sys"

var udpDivert *divert.Handle

func dllInit(_divertDll string) {
	_, err := os.Stat(_divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", _divertDll)
	}
}

func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	// 过滤器：仅入站、来自 53 端口的 UDP 包
	// !impostor 确保不是我们自己注入的包
	filter := "inbound and !impostor and udp.SrcPort = 53"
	var err error
	dnsDivert, err = divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("WinDivert open failed: %v", err)
		return
	}
	defer dnsDivert.Close()

	inboundBuf := make([]byte, 2048)
	addr := divert.Address{}

	for {
		recvLen, err := dnsDivert.Recv(inboundBuf, &addr)
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
					dnsRecords.Add(rr.A.String(), name)
					//log.Printf("[DNS A] 域名: %s -> IP: %s", name, rr.A.String())
				// 这里可以执行你的 GeoIP 分流逻辑
				case *dns.AAAA:
					//dnsRecords.Add(rr.AAAA.String(), name)
					//log.Printf("[DNS AAAA] 域名: %s -> IPv6: %s", name, rr.AAAA.String())
				}
			}
		}
	}
}

func NetEvent(pid int, excludePorts *sync.Map) {
	excludePorts.Clear()
	if pid > 0 {
		bindPorts, _ := netstat.GetTcpBindList(pid, true)
		for _, v := range bindPorts {
			excludePorts.Store(fmt.Sprintf("%d", v), 1)
		}
	}

	var filter = fmt.Sprintf("processId=%d or processId=%d", os.Getpid(), pid)
	var err error
	eventDivert, err = divert.Open(filter, divert.LayerSocket, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}
	defer eventDivert.Close()
	//udp事件监控
	inboundBuf := make([]byte, 2024)
	addr := divert.Address{}
	for {
		_, err := eventDivert.Recv(inboundBuf, &addr)
		if err != nil {
			log.Printf("winDivert recv failed: %v\r\n", err)
			return
		}
		switch addr.Event() {
		case divert.EventSocketBind:
			//	log.Printf("ip: %s\r\n", ip.String())
			excludePorts.Store(fmt.Sprintf("%d", addr.Flow().LocalPort), 1)
		case divert.EventSocketConnect:
			excludePorts.Store(fmt.Sprintf("%d", addr.Flow().LocalPort), 1)
		case divert.EventSocketClose:
			//ip := net.IP(addr.Flow().LocalAddress[:4])
			excludePorts.Delete(fmt.Sprintf("%d", addr.Flow().LocalPort))
		}
	}
}

func RedirectAllTCP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map) {
	// 过滤器逻辑：拦截所有 TCP 流量，但排除：
	// 1. 代理监听端口 (7080)
	// 2. 代理程序用于外连的排除 IP (127.0.0.2)
	filter := fmt.Sprintf(
		"!loopback and outbound and tcp and tcp.DstPort != %d",
		proxyPort,
	)
	var err error
	tcpDivert, err = divert.Open(filter, divert.LayerNetwork, 0, divert.FlagDefault)
	if err != nil {
		log.Fatalf("WinDivert 打开失败: %v", err)
	}
	defer tcpDivert.Close()

	log.Printf("全端口透明代理已启动...\n, 代理端口: %d\n", proxyPort)

	var addr divert.Address
	buf := make([]byte, 1024*10)
	var modifiedPacket bool
	for {
		n, err := tcpDivert.Recv(buf, &addr)
		if err != nil || n == 0 {
			continue
		}

		packet := buf[:n]
		outbound := (addr.Flags & (0x01 << 1)) != 0 // 判断是否为出站数据包
		srcIP, srcPort, dstIP, dstPort := comm.ParsePacketInfoFast(packet)
		modifiedPacket = false
		if outbound && srcIP != nil {
			// 场景 A：代理程序发送给客户端的回包 (此时 SrcPort 是 proxyPort)
			if srcPort == proxyPort {
				// 通过映射表查找该连接原始对应的客户端端口
				key := fmt.Sprintf("%d", dstPort)
				if origPort, ok := originalPorts.Load(key); ok {
					// 将包伪装成：从“真实服务器”发往“客户端原始端口”
					comm.ModifyPacketFast(packet, dstIP, origPort.(uint16), srcIP, dstPort)
					// 修改为入站包，欺骗协议栈
					addr.Flags = addr.Flags & ^uint8(0x02)
					modifiedPacket = true
				}
			} else {
				//本进程的过滤
				if _, ok := excludePorts.Load(fmt.Sprintf("%d", srcPort)); !ok {

					if comm.IsProxyRequiredFast(dstIP.String()) {
						// 场景 B：客户端发起的原始请求包 (访问任意端口)
						// 记录原始端口信息，以便后续回包还原
						key := fmt.Sprintf("%d", srcPort)
						originalPorts.Store(key, dstPort)
						//log.Printf("save key:%s->%d\r\n", key, int(dstPort))
						// 反射逻辑：将目标 IP 改为本地，端口改为代理端口，并设为入站
						comm.ModifyPacketFast(packet, dstIP, srcPort, srcIP, proxyPort)
						//	log.Printf("srcIP:%s -> %s\r\n", dstIP, srcIP)
						addr.Flags = addr.Flags & ^uint8(0x02)
						modifiedPacket = true
					}
				}
			}
		}

		if modifiedPacket {
			// 重新计算校验和并发送
			divert.CalcChecksums(packet, &addr, 0)
			tcpDivert.Send(packet, &addr)
		} else {
			// 其它包原样放行
			tcpDivert.Send(packet, &addr)
		}
	}
}

func CloseWinDivert() {
	if dnsDivert != nil {
		dnsDivert.Close()
	}
	if tcpDivert != nil {
		tcpDivert.Close()
	}
	if udpDivert != nil {
		udpDivert.Close()
	}
	if eventDivert != nil {
		eventDivert.Close()
	}
}

func CloseNetEvent() {
	if eventDivert != nil {
		eventDivert.Close()
	}
}

func RedirectAllUDP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map) {
	// 过滤器：拦截出站 UDP，排除回环、DNS(53) 和 代理端口自身
	filter := fmt.Sprintf(
		"!loopback and outbound and udp and udp.DstPort != 53 and udp.DstPort != %d",
		proxyPort,
	)
	var err error
	udpDivert, err = divert.Open(filter, divert.LayerNetwork, 0, divert.FlagDefault)
	if err != nil {
		log.Printf("WinDivert UDP 打开失败: %v", err)
		return
	}
	defer udpDivert.Close()

	var addr divert.Address
	buf := make([]byte, 1024*10)
	for {
		n, err := udpDivert.Recv(buf, &addr)
		if err != nil || n == 0 {
			continue
		}

		packet := buf[:n]
		outbound := (addr.Flags & (0x01 << 1)) != 0
		srcIP, srcPort, dstIP, dstPort := comm.ParsePacketInfoFast(packet)

		if outbound && srcIP != nil {
			// 1. 处理代理发回给客户端的包 (源端口是 proxyPort)
			if srcPort == proxyPort {
				key := fmt.Sprintf("udp:%d", dstPort) // 这里的 dstPort 是客户端的临时端口
				if origPort, ok := originalPorts.Load(key); ok {

					comm.ModifyPacketFast(packet, dstIP, origPort.(uint16), srcIP, dstPort)
					addr.Flags = addr.Flags & ^uint8(0x02) // 设为入站
					divert.CalcChecksums(packet, &addr, 0)
					udpDivert.Send(packet, &addr)
					continue
				}
			} else {
				// 2. 处理客户端发出的请求包
				// 排除代理程序自身的流量
				if _, ok := excludePorts.Load(fmt.Sprintf("%d", srcPort)); !ok {
					if comm.IsProxyRequiredFast(dstIP.String()) {
						// 记录原始目标地址：客户端端口 -> 原始目标IP:端口
						key := fmt.Sprintf("udp:%d", srcPort)
						originalPorts.Store(key, dstPort)

						// 重定向：目标改为本地 IP，端口改为代理端口
						comm.ModifyPacketFast(packet, dstIP, srcPort, srcIP, proxyPort)

						addr.Flags = addr.Flags & ^uint8(0x02) // 设为入站
						divert.CalcChecksums(packet, &addr, 0)
						udpDivert.Send(packet, &addr)
						continue
					}
				}
			}
		}
		// 默认原样放行
		udpDivert.Send(packet, &addr)
	}
}
