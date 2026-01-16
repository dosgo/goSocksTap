package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	divert "github.com/imgk/divert-go"
	"golang.org/x/net/proxy"
)

var port uint16 = 443
var proxy_port uint16 = 7080
var alt_port uint16 = 7081
var useSocks = false

func main() {

	go startLocalRelay()

	// 2. 使用Network层重定向数据包
	redirectTCPPackets()
}

// 重定向TCP数据包
func redirectTCPPackets() {
	filter := fmt.Sprintf("ip and tcp and (tcp.DstPort == %d or tcp.DstPort == %d or tcp.DstPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d or tcp.SrcPort == %d)",
		port, proxy_port, alt_port, port, proxy_port, alt_port)
	handle, err := divert.Open(
		filter,
		divert.LayerNetwork, // Network层修改数据包
		0,
		divert.FlagDefault,
	)
	if err != nil {
		log.Fatalf("Network层打开失败: %v", err)
	}
	defer handle.Close()
	fmt.Println("开始重定向数据包...")
	var addr divert.Address
	buf := make([]byte, 2048)
	var modifiedPacket []byte
	for {
		n, err := handle.Recv(buf, &addr)
		if err != nil {
			log.Printf("接收数据包失败: %v", err)
			continue
		}
		if n == 0 {
			continue
		}
		packet := buf[:n]
		outbound := (addr.Flags & (0x01 << 1)) != 0
		srcAddr, srcPort, dstAddr, dstPort := parsePacketInfo(packet)
		if outbound {
			if dstPort == uint16(port) {
				// Reflect: PORT ---> PROXY
				//  UINT32 dstAddr = ip_header->dstAddr;
				// tcp_header->DstPort = htons(proxy_port);
				// ip_header->dstAddr = ip_header->srcAddr;
				//ip_header->srcAddr = dstAddr;

				// addr.Outbound = FALSE;
				modifiedPacket, err = modifydPacket(packet, dstAddr, srcPort, srcAddr, proxy_port)
				if err != nil {
					fmt.Printf("err1:%+v\r\n", err)
				}
				addr.Flags = addr.Flags & ^uint8(0x02)
			} else if srcPort == uint16(proxy_port) {
				// Reflect: PROXY ---> PORT
				//  UINT32 dst_addr = ip_header->DstAddr;
				// tcp_header->SrcPort = htons(port);
				//  ip_header->DstAddr = ip_header->SrcAddr;
				//  ip_header->SrcAddr = dst_addr;

				modifiedPacket, err = modifydPacket(packet, dstAddr, port, srcAddr, dstPort)
				if err != nil {
					fmt.Printf("err2:%+v\r\n", err)
				}

				//addr.Outbound = FALSE;
				addr.Flags = addr.Flags & ^uint8(0x02)
			} else if dstPort == uint16(alt_port) {
				// Redirect: ALT ---> PORT
				// tcp_header->DstPort = htons(port);

				modifiedPacket, err = modifydPacket(packet, srcAddr, srcPort, dstAddr, port)
				if err != nil {
					fmt.Printf("err3:%+v\r\n", err)
				}
			}
		} else {
			if srcPort == uint16(port) {
				// Redirect: PORT ---> ALT
				// tcp_header->SrcPort = htons(alt_port);

				modifiedPacket, err = modifydPacket(packet, srcAddr, alt_port, dstAddr, dstPort)
				if err != nil {
					fmt.Printf("err4:%+v\r\n", err)
				}
			}
		}

		if modifiedPacket != nil {
			// 发送修改后的包
			//	divert.CalcChecksums(modifiedPacket, &addr, 0)

			//fmt.Printf("src packet:%+v modifiedPacket:%+v\r\n", packet, modifiedPacket)
			if _, err := handle.Send(modifiedPacket, &addr); err != nil {
				log.Printf("发送数据包失败: %v", err)
			}
			modifiedPacket = nil
		} else {
			if _, err := handle.Send(packet, &addr); err != nil {
				log.Printf("发送数据包失败: %v", err)
			}
		}

	}
}

// 修改入站包
func modifydPacket(packet []byte, newSrcIP net.IP, newSrcPort uint16, newDestIp net.IP, newDestPort uint16) ([]byte, error) {
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	if pkt.ErrorLayer() != nil {
		return nil, fmt.Errorf("无法解析数据包")
	}
	// 获取IP层
	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil, fmt.Errorf("不是IPv4数据包")
	}
	ip, _ := ipLayer.(*layers.IPv4)

	// 获取TCP层
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil, fmt.Errorf("不是TCP数据包")
	}
	tcp, _ := tcpLayer.(*layers.TCP)

	ip.SrcIP = newSrcIP
	tcp.SrcPort = layers.TCPPort(newSrcPort)

	ip.DstIP = newDestIp
	tcp.DstPort = layers.TCPPort(newDestPort)
	// 重置校验和
	ip.Checksum = 0
	tcp.Checksum = 0
	// 重新序列化
	return serializePacket(ip, tcp, pkt.ApplicationLayer())
}

// 解析数据包信息
func parsePacketInfo(packet []byte) (localIP net.IP, localPort uint16, remoteIP net.IP, remotePort uint16) {
	// 使用gopacket解析数据包
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.NoCopy)
	if pkt.ErrorLayer() != nil {
		// 如果是IPv4解析失败，尝试IPv6
		pkt = gopacket.NewPacket(packet, layers.LayerTypeIPv6, gopacket.NoCopy)
		if pkt.ErrorLayer() != nil {
			return nil, 0, nil, 0
		}
	}

	// 获取网络层（IP层）
	var networkLayer gopacket.NetworkLayer
	if ipv4Layer := pkt.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		networkLayer = ipv4Layer.(gopacket.NetworkLayer)
	} else if ipv6Layer := pkt.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		networkLayer = ipv6Layer.(gopacket.NetworkLayer)
	} else {
		return nil, 0, nil, 0
	}

	// 获取传输层（TCP层）
	var transportLayer gopacket.TransportLayer
	if tcpLayer := pkt.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		transportLayer = tcpLayer.(gopacket.TransportLayer)
	} else {
		return nil, 0, nil, 0
	}

	// 提取IP和端口信息
	srcIP := networkLayer.NetworkFlow().Src()
	dstIP := networkLayer.NetworkFlow().Dst()
	srcPort := transportLayer.TransportFlow().Src()
	dstPort := transportLayer.TransportFlow().Dst()

	// 转换为具体的类型
	srcIPAddr := net.ParseIP(srcIP.String())
	dstIPAddr := net.ParseIP(dstIP.String())

	// 端口转换为uint16
	var srcPortNum, dstPortNum uint16
	fmt.Sscanf(srcPort.String(), "%d", &srcPortNum)
	fmt.Sscanf(dstPort.String(), "%d", &dstPortNum)

	return srcIPAddr, srcPortNum, dstIPAddr, dstPortNum
}

func startLocalRelay() {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", proxy_port))
	if err != nil {
		log.Fatalf("Relay 监听失败: %v", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go proxy_connection_handler(conn)
	}
}
func proxy_connection_handler(conn net.Conn) {
	defer conn.Close()
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		targetIP := tcpAddr.IP.String()
		fmt.Printf("targetIP:%s\r\n", targetIP)
		var lConn net.Conn
		var err error
		if useSocks {
			dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:10808", nil, proxy.Direct)
			if err != nil {
				log.Printf("SOCKS5 拨号失败: %v", err)
				return
			}
			// ... err check
			lConn, err = dialer.Dial("tcp", net.JoinHostPort(targetIP, strconv.Itoa(int(port))))
		} else {
			lConn, err = net.Dial("tcp", net.JoinHostPort(targetIP, strconv.Itoa(int(alt_port))))
		}
		if err != nil {
			fmt.Printf("failed to connect socket err:%+v\r\n", err)
			return
		}
		defer lConn.Close()
		go io.Copy(conn, lConn)
		io.Copy(lConn, conn)
	} else {
		fmt.Printf("failed to get tcpAddr\r\n")
	}
	return
}

func serializePacket(ip *layers.IPv4, tcp *layers.TCP, appLayer gopacket.ApplicationLayer) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	var payload []byte
	if appLayer != nil {
		payload = appLayer.Payload()
	}
	err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload))
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
