//go:build windows
// +build windows

package winDivert

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/imgk/divert-go"
)

func RedirectData(proxyPort uint16) {
	// 过滤器：拦截 TCP，排除掉发往 1080 的包以防死循环
	// 注意：在反射模式下，必须确保过滤器不会拦截代理程序连接真实服务器产生的 Outbound 包
	filter := fmt.Sprintf(
		"tcp and ip.SrcAddr != 127.0.0.1 and ip.DstAddr != 127.0.0.1 and "+
			"tcp.DstPort != %d and tcp.SrcPort != %d",
		proxyPort, proxyPort,
	)

	fmt.Printf("filter:%s\r\n", filter)

	handle, err := divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// 启动 TCP 代理服务器
	go startProxyServer(proxyPort)

	packet := make([]byte, 65535)
	var addr divert.Address // 使用你的结构体

	fmt.Println("服务已启动：全端口反射模式 (无 NAT 表)")

	for {
		// 这里需要根据你使用的绑定库，将底层的 addr 指针传入
		n, err := handle.Recv(packet, (*divert.Address)(&addr))
		if err != nil {
			continue
		}

		if n < 20 || packet[0]>>4 != 4 {
			continue
		}

		ihl := int(packet[0]&0x0F) * 4
		isOutbound := (addr.Flags & 0x01) != 0
		log.Printf("收到包长度: %d, Flags 原始值: %d (二进制: %08b)", n, addr.Flags, addr.Flags)
		//isOutbound := (addr.union[0] & 0x01) != 0
		if isOutbound {
			// --- 阶段 A：劫持出站包并弹回本地 ---
			// 1. 提取原始目标 (DstIP:DstPort)
			origDstIP := make([]byte, 4)
			copy(origDstIP, packet[16:20])
			origDstPort := packet[ihl+2 : ihl+4]

			// 2. 镜像交换：把目标 IP:Port 藏到源地址字段里
			// 这样代理程序 Accept 时，RemoteAddr 就是真正的目标
			copy(packet[12:16], origDstIP)       // SrcIP <- Original DstIP
			copy(packet[ihl:ihl+2], origDstPort) // SrcPort <- Original DstPort

			// 3. 修改目的地为本地代理端口 1080
			copy(packet[16:20], []byte{127, 0, 0, 1})
			binary.BigEndian.PutUint16(packet[ihl+2:ihl+4], proxyPort)

			// 4. 方向反转：出站(1) -> 入站(0)
			addr.Flags &= ^uint8(0x01)

			fmt.Printf("eeeee\r\n")

		} else {
			// --- 阶段 B：处理入站包 (暂时不需要特殊处理，由协议栈自动路由) ---
			// 或者是处理来自远程服务器的回包逻辑，streamdump 通过 alt_port 解决
			// 如果你只做简单反射，这里保持原样转发给协议栈即可
		}

		divert.CalcChecksums(packet[:n], (*divert.Address)(&addr), 0)
		handle.Send(packet[:n], (*divert.Address)(&addr))
	}
}

func startProxyServer(proxyPort uint16) {
	l, _ := net.Listen("tcp", "127.0.0.1:"+fmt.Sprint(proxyPort))
	for {
		conn, _ := l.Accept()
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
