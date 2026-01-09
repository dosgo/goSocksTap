//go:build windows
// +build windows

package winDivert

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/imgk/divert-go"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type ForwardInfo1 struct {
	SrcIP       net.IP
	SrcPort     uint16
	OrigDstIP   net.IP
	OrigDstPort uint16
}

var natTable sync.Map

func RedirectTCPNat(proxyPort uint16, proxyAddr string, localHost bool) {

	go startProxyServer(proxyPort)
	if _, err := os.Stat(divertDll); err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var forward sync.Map // key: uint16 (local port) -> value: ForwardInfo

	// 出站拦截：拦截所有发往外部的 TCP 包
	go func() {
		recvBuf := make([]byte, 65535)
		addr := divert.Address{}

		// 过滤条件：拦截 TCP 且 目的地址不是代理服务器地址（防止死循环）
		filterOut := fmt.Sprintf("outbound and tcp and ip.DstAddr != %s and tcp.DstPort != %d", proxyAddr, proxyPort)

		var err error
		outboundDivert, err = divert.Open(filterOut, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			log.Printf("WinDivert outbound open failed: %v\r\n", err)
			return
		}
		defer outboundDivert.Close()

		for winDivertRun {
			recvLen, err := outboundDivert.Recv(recvBuf, &addr)
			if err != nil {
				continue
			}

			// 1. 解析 IP 层确定 TCP 头部起始位置
			isIpv6 := recvBuf[0]>>4 == 6
			var ipHeadLen int
			var srcIP, dstIP net.IP

			if isIpv6 {
				ipHeadLen = 40
				ipHeader, _ := ipv6.ParseHeader(recvBuf[:recvLen])
				srcIP, dstIP = ipHeader.Src, ipHeader.Dst
			} else {
				ipHeadLen = int(recvBuf[0]&0xF) * 4
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])
				srcIP, dstIP = ipHeader.Src, ipHeader.Dst
			}
			fmt.Printf("recvBuf:%+v\r\n", recvBuf[:recvLen])
			// 2. 解析 TCP 头部 (端口在 TCP 头的前 4 字节)
			// [0:2] 是 SrcPort, [2:4] 是 DstPort
			tcpSrcPort := binary.BigEndian.Uint16(recvBuf[ipHeadLen : ipHeadLen+2])
			// tcpDstPort := binary.BigEndian.Uint16(recvBuf[ipHeadLen+2 : ipHeadLen+4])

			// 3. 记录原始信息，以便回程包还原
			forward.Store(tcpSrcPort, ForwardInfo{
				Dst:               dstIP,
				Src:               srcIP,
				InterfaceIndex:    addr.Network().InterfaceIndex,
				SubInterfaceIndex: addr.Network().SubInterfaceIndex,
				LastTime:          time.Now().Unix(),
			})

			// 4. 修改目的地址和端口为代理服务器
			// 修改 IP 层
			if !isIpv6 {
				ipHeader, _ := ipv4.ParseHeader(recvBuf[:recvLen])
				ipHeader.Dst = net.ParseIP(proxyAddr)
				if localHost {
					ipHeader.Src = net.ParseIP(proxyAddr)
				}
				newIPBuf, _ := ipHeader.Marshal()
				//fmt.Printf("newIPBuf len:%d recvLen:%d\r\n", len(newIPBuf), recvLen)
				copy(recvBuf, newIPBuf)
			}
			//fmt.Printf("ipHeadLen:%d\r\n", ipHeadLen)
			// 修改 TCP 层目的端口
			binary.BigEndian.PutUint16(recvBuf[ipHeadLen+2:ipHeadLen+4], proxyPort)
			fmt.Printf("recvBuf2:%+v\r\n", recvBuf[:recvLen])
			// 5. 修正 Loopback 标志（如果是发给本地代理）
			if localHost {
				addr.Network().InterfaceIndex = 1
				addr.Network().SubInterfaceIndex = 0
				addr.Flags |= 0x04 // WINDIVERT_ADDRESS_FLAG_LOOPBACK
			}

			// 6. 重新计算校验和并发送
			divert.CalcChecksums(recvBuf[:recvLen], &addr, 0)
			outboundDivert.Send(recvBuf[:recvLen], &addr)
		}
	}()

	// 入站拦截：拦截代理服务器回传给客户端的包，并伪装成目标服务器
	go func() {
		inboundBuf := make([]byte, 65535)
		inboundAddr := divert.Address{}

		filterIn := fmt.Sprintf("inbound and tcp and tcp.SrcPort == %d and ip.SrcAddr == %s", proxyPort, proxyAddr)

		var err error
		inboundDivert, err = divert.Open(filterIn, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
		if err != nil {
			log.Printf("WinDivert inbound open failed: %v\r\n", err)
			return
		}
		defer inboundDivert.Close()

		for winDivertRun {
			recvLen, err := inboundDivert.Recv(inboundBuf, &inboundAddr)
			if err != nil {
				continue
			}

			isIpv6 := inboundBuf[0]>>4 == 6
			var ipHeadLen int
			if isIpv6 {
				ipHeadLen = 40
			} else {
				ipHeadLen = int(inboundBuf[0]&0xF) * 4
			}

			// 获取目的端口，寻找原始对应关系
			tcpDstPort := binary.BigEndian.Uint16(inboundBuf[ipHeadLen+2 : ipHeadLen+4])
			val, ok := forward.Load(tcpDstPort)
			if !ok {
				inboundDivert.Send(inboundBuf[:recvLen], &inboundAddr)
				continue
			}
			info := val.(ForwardInfo)

			// 还原源地址为原始目标服务器地址
			if !isIpv6 {
				ipHeader, _ := ipv4.ParseHeader(inboundBuf[:recvLen])
				ipHeader.Src = info.Dst
				if localHost {
					ipHeader.Dst = info.Src
				}
				newIPBuf, _ := ipHeader.Marshal()
				copy(inboundBuf, newIPBuf)
			}

			// 还原源端口为原始目标服务器端口 (这里假设是针对特定流量，或者你需要从 info 里额外存原始目标端口)
			// 注意：在前面的 outbound 里，我们通常需要保存原始目标端口
			// 假设你之前的拦截是基于端口映射的，这里修改 SrcPort：
			// binary.BigEndian.PutUint16(inboundBuf[ipHeadLen:ipHeadLen+2], info.OriginalDstPort)

			if localHost {
				inboundAddr.Network().InterfaceIndex = info.InterfaceIndex
				inboundAddr.Network().SubInterfaceIndex = info.SubInterfaceIndex
				inboundAddr.Flags &= ^uint8(0x04) // 清除 Loopback 标志
			}

			divert.CalcChecksums(inboundBuf[:recvLen], &inboundAddr, 0)
			inboundDivert.Send(inboundBuf[:recvLen], &inboundAddr)
		}
	}()
}

func startProxyServer(proxyPort uint16) {
	l, _ := net.Listen("tcp", "127.0.0.1:"+fmt.Sprint(proxyPort))
	for {
		fmt.Printf("Accept\r\n")
		conn, _ := l.Accept()
		fmt.Printf("eee111\r\n")
		go func(c net.Conn) {
			defer c.Close()

			// 【这就是你找回端口的地方】
			// 因为我们在 WinDivert 里把 DstPort 换到了 SrcPort 的位置
			// 这里的 RemoteAddr 拿到的就是 "1.1.1.1:443"
			target := c.RemoteAddr().String()
			fmt.Printf("成功拦截并识别目标: %s\n", target)

			// 剩下的就是常规转发逻辑
			remote, err := net.Dial("tcp", target)
			if err != nil {
				return
			}
			defer remote.Close()

			// 双向数据拷贝
			go io.Copy(remote, c)
			io.Copy(c, remote)
		}(conn)
	}
}
