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

	divert "github.com/imgk/divert-go"
	"golang.org/x/net/proxy"
)

// 配置参数
var (
	socksAddr        = ""
	proxyPort uint16 = 7080
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
			//	log.Printf("ip: %s\r\n", ip.String())
			myPorts.Store(fmt.Sprintf("%d", addr.Flow().LocalPort), 1)
		case divert.EventSocketConnect:
			myPorts.Store(fmt.Sprintf("%d", addr.Flow().LocalPort), 1)
		case divert.EventSocketClose:
			//ip := net.IP(addr.Flow().LocalAddress[:4])
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
	// 2. 代理程序用于外连的排除 IP (127.0.0.2)
	filter := fmt.Sprintf(
		"!loopback and outbound and tcp and tcp.DstPort != %d",
		proxyPort,
	)

	handle, err := divert.Open(filter, divert.LayerNetwork, 0, divert.FlagDefault)
	if err != nil {
		log.Fatalf("WinDivert 打开失败: %v", err)
	}
	defer handle.Close()

	log.Printf("全端口透明代理已启动...\n, 代理端口: %d\n", proxyPort)

	var addr divert.Address
	buf := make([]byte, 1024*10)
	var modifiedPacket bool
	for {
		n, err := handle.Recv(buf, &addr)
		if err != nil || n == 0 {
			continue
		}

		packet := buf[:n]
		outbound := (addr.Flags & (0x01 << 1)) != 0 // 判断是否为出站数据包
		srcIP, srcPort, dstIP, dstPort := parsePacketInfoFast(packet)
		modifiedPacket = false
		if outbound && srcIP != nil {
			// 场景 A：代理程序发送给客户端的回包 (此时 SrcPort 是 proxyPort)
			if srcPort == proxyPort {
				// 通过映射表查找该连接原始对应的客户端端口
				key := fmt.Sprintf("%d", dstPort)
				if origPort, ok := originalPorts.Load(key); ok {
					// 将包伪装成：从“真实服务器”发往“客户端原始端口”
					modifyPacketFast(packet, dstIP, origPort.(uint16), srcIP, dstPort)
					// 修改为入站包，欺骗协议栈
					addr.Flags = addr.Flags & ^uint8(0x02)
					modifiedPacket = true
				}
			} else {
				//本进程的过滤
				if _, ok := myPorts.Load(fmt.Sprintf("%d", srcPort)); !ok {
					// 场景 B：客户端发起的原始请求包 (访问任意端口)
					// 记录原始端口信息，以便后续回包还原
					key := fmt.Sprintf("%d", srcPort)
					originalPorts.Store(key, dstPort)
					//log.Printf("save key:%s->%d\r\n", key, int(dstPort))
					// 反射逻辑：将目标 IP 改为本地，端口改为代理端口，并设为入站
					modifyPacketFast(packet, dstIP, srcPort, srcIP, proxyPort)
					//	log.Printf("srcIP:%s -> %s\r\n", dstIP, srcIP)
					addr.Flags = addr.Flags & ^uint8(0x02)
					modifiedPacket = true
				}
			}
		}

		if modifiedPacket {
			// 重新计算校验和并发送
			divert.CalcChecksums(packet, &addr, 0)
			handle.Send(packet, &addr)
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
	log.Printf("startLocalRelay\r\n")
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
		//	log.Printf("[拦截流量] 目标: %s\n", tcpAddr.String())
		key := fmt.Sprintf("%d", tcpAddr.Port)
		if origPort, ok := originalPorts.Load(key); ok {
			/*
				dialer := getDialer()
				if dialer == nil {
					return
				}
			*/
			var targetConn net.Conn
			var err error
			if socksAddr != "" {
				dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
				if err != nil {
					log.Printf("SOCKS5 拨号失败: %v", err)
					return
				}
				// ... err check
				targetConn, err = dialer.Dial("tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16)))))
			} else {
				targetConn, err = net.DialTimeout("tcp", net.JoinHostPort(tcpAddr.IP.String(), strconv.Itoa(int(origPort.(uint16)))), 5*time.Second)
			}
			if err != nil || targetConn == nil {
				log.Printf("connect err: %v", err)
				return
			}
			defer myPorts.Delete(fmt.Sprintf("%d", targetConn.LocalAddr().(*net.TCPAddr).Port))
			//log.Printf("src port:%d\r\n", targetConn.LocalAddr().(*net.TCPAddr).Port)
			defer targetConn.Close()
			// 双向数据拷贝 (你可以在这里打印/记录 payload 内容)
			go io.Copy(targetConn, conn)
			io.Copy(conn, targetConn)
		} else {
			log.Printf("err addr:%s\r\n", tcpAddr.String())
		}
	}
}

func getDialer() *net.Dialer {
	randomPort, err := GetRandomPort()
	if err != nil {
		log.Printf("获取随机端口失败: %v\n", err)
		return nil
	}
	myPorts.Store(fmt.Sprintf("%d", randomPort), 1)
	// 使用 Dialer 绑定到这个随机端口
	return &net.Dialer{
		Timeout: 5 * time.Second,
		LocalAddr: &net.TCPAddr{
			Port: randomPort, // 使用随机端口
		},
	}
}
func GetRandomPort() (int, error) {
	// 监听任意地址的0端口，系统会分配随机端口
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port, nil
}

func parsePacketInfoFast(packet []byte) (net.IP, uint16, net.IP, uint16) {
	// 1. 基础长度检查
	if len(packet) < 20 {
		return nil, 0, nil, 0
	}

	// 2. 检查是否为 IPv4
	if (packet[0] >> 4) != 4 {
		return nil, 0, nil, 0
	}

	// 3. 重要：拷贝 IP 字节，防止后续修改 packet 时影响变量值
	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	copy(srcIP, packet[12:16])
	copy(dstIP, packet[16:20])

	// 4. 动态计算 TCP 偏移量
	ihl := int(packet[0]&0x0F) * 4

	// 5. 再次安全检查：确保 packet 长度足够读取 TCP 端口 (ihl + 4 字节)
	if len(packet) < ihl+4 {
		return nil, 0, nil, 0
	}

	srcPort := uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
	dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])

	return srcIP, srcPort, dstIP, dstPort
}

func modifyPacketFast(packet []byte, newSrcIP net.IP, newSrcPort uint16, newDstIP net.IP, newDstPort uint16) {
	// 1. 修改 IP (IPv4 头部固定 12-19 字节)
	copy(packet[12:16], newSrcIP.To4())
	copy(packet[16:20], newDstIP.To4())

	// 2. 动态计算 TCP 偏移量 (IHL)
	ihl := int(packet[0]&0x0F) * 4

	// 3. 修改端口 (基于 ihl 偏移)
	packet[ihl] = uint8(newSrcPort >> 8)
	packet[ihl+1] = uint8(newSrcPort)
	packet[ihl+2] = uint8(newDstPort >> 8)
	packet[ihl+3] = uint8(newDstPort)
}
