package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	divert "github.com/imgk/divert-go"
)

// 配置参数
var (
	proxyPort uint16 = 7080
	// 排除 IP：代理程序在“连接目标”时强制绑定此 IP，用于绕过驱动拦截
)

var (
	// 记录 原始客户端端口映射
	// Key: {服务器IP, 客户端IP, 代理端口}, Value: 客户端原始端口
	originalPorts = sync.Map{}
	myPorts       = sync.Map{}
)

func NetEvent(pid uint32) {
	var filter = fmt.Sprintf("processId=%d or processId=%d", os.Getpid(), pid)
	eventDivert, err := divert.Open(filter, divert.LayerSocket, divert.PriorityDefault, divert.FlagSniff|divert.FlagRecvOnly)
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
			myPorts.Store(fmt.Sprintf("%d", addr.Flow().LocalPort), time.Now().Unix())
		case divert.EventSocketClose:
			myPorts.Delete(fmt.Sprintf("%d", addr.Flow().LocalPort))
		}
	}

}

func main() {
	// 1. 启动本地代理中转服务器
	go startLocalRelay()
	go NetEvent(0)
	// 2. 开启 WinDivert 拦截并重定向所有 TCP 流量
	redirectAllTCP()
	bufio.NewReader(os.Stdin).ReadRune()
}

func redirectAllTCP() {
	// 过滤器逻辑：拦截所有 TCP 流量，但排除：
	// 1. 代理监听端口 (7080)
	filter := fmt.Sprintf(
		"outbound and tcp and tcp.DstPort != %d",
		proxyPort,
	)

	handle, err := divert.Open(filter, divert.LayerNetwork, 0, divert.FlagDefault)
	if err != nil {
		log.Fatalf("WinDivert 打开失败: %v", err)
	}
	defer handle.Close()

	fmt.Printf("全端口透明代理已启动...\n, 代理端口: %d\n", proxyPort)

	var addr divert.Address
	buf := make([]byte, 1600)

	for {
		n, err := handle.Recv(buf, &addr)
		if err != nil || n == 0 {
			continue
		}

		packet := buf[:n]
		outbound := (addr.Flags & (0x01 << 1)) != 0 // 判断是否为出站数据包
		srcIP, srcPort, dstIP, dstPort := parsePacketInfo(packet)

		var modifiedPacket []byte
		if outbound && srcIP != nil {
			// 场景 A：代理程序发送给客户端的回包 (此时 SrcPort 是 proxyPort)
			if srcPort == proxyPort {
				// 通过映射表查找该连接原始对应的客户端端口
				key := fmt.Sprintf("%d", dstPort)
				if origPort, ok := originalPorts.Load(key); ok {
					// 将包伪装成：从“真实服务器”发往“客户端原始端口”
					modifiedPacket, _ = modifyPacket(packet, dstIP, origPort.(uint16), srcIP, dstPort)
					// 修改为入站包，欺骗协议栈
					addr.Flags = addr.Flags & ^uint8(0x02)
				}
			} else {
				//本进程的过滤
				if _, ok := myPorts.Load(fmt.Sprintf("%d", srcPort)); !ok {

					// 场景 B：客户端发起的原始请求包 (访问任意端口)
					// 记录原始端口信息，以便后续回包还原
					key := fmt.Sprintf("%d", srcPort)
					originalPorts.Store(key, dstPort)
					//fmt.Printf("save key:%s->%d\r\n", key, int(dstPort))
					// 反射逻辑：将目标 IP 改为本地，端口改为代理端口，并设为入站
					modifiedPacket, _ = modifyPacket(packet, dstIP, srcPort, srcIP, proxyPort)
					//	fmt.Printf("srcIP:%s -> %s\r\n", dstIP, srcIP)
					addr.Flags = addr.Flags & ^uint8(0x02)
				}
			}
		}

		if modifiedPacket != nil {
			// 重新计算校验和并发送
			//divert.CalcChecksums(modifiedPacket, &addr, 0)
			handle.Send(modifiedPacket, &addr)
		} else {
			// 其它包原样放行
			handle.Send(packet, &addr)
		}
	}
}

// 代理中转逻辑
func startLocalRelay() {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", proxyPort))
	if err != nil {
		log.Fatalf("代理监听失败: %v", err)
	}
	fmt.Printf("startLocalRelay\r\n")
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		// 核心点：由于使用了反射，conn.RemoteAddr() 实际上是原始的目标服务器地址
		fmt.Printf("[拦截流量] 目标: %s\n", tcpAddr.String())
		key := fmt.Sprintf("%d", tcpAddr.Port)
		if origPort, ok := originalPorts.Load(key); ok {
			tcpAddr.Port = int(origPort.(uint16))
			targetConn, err := net.Dial("tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16)))))
			if err != nil {
				log.Printf("无法连接目标服务器: %v", err)
				return
			}
			defer targetConn.Close()
			// 双向数据拷贝 (你可以在这里打印/记录 payload 内容)
			go io.Copy(targetConn, conn)
			io.Copy(conn, targetConn)
		}
	}
}

// 工具函数：解析 IP 和端口
func parsePacketInfo(packet []byte) (net.IP, uint16, net.IP, uint16) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.NoCopy)
	if ipLayer := pkt.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip := ipLayer.(*layers.IPv4)
		if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			return ip.SrcIP, uint16(tcp.SrcPort), ip.DstIP, uint16(tcp.DstPort)
		}
	}
	return nil, 0, nil, 0
}

// 工具函数：构造并序列化新数据包
func modifyPacket(packet []byte, newSrcIP net.IP, newSrcPort uint16, newDstIP net.IP, newDstPort uint16) ([]byte, error) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	tcp, _ := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP)
	//fmt.Printf("newSrcIP:%+v\r\n", newSrcIP)

	ip.SrcIP, tcp.SrcPort = newSrcIP, layers.TCPPort(newSrcPort)
	ip.DstIP, tcp.DstPort = newDstIP, layers.TCPPort(newDstPort)

	// 重置校验和
	ip.Checksum, tcp.Checksum = 0, 0

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	tcp.SetNetworkLayerForChecksum(ip)

	payload := []byte{}
	if app := pkt.ApplicationLayer(); app != nil {
		payload = app.Payload()
	}

	err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	return buf.Bytes(), err
}
