//go:build !windows
// +build !windows

package forward

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/dosgo/goSocksTap/comm/udpProxy"
	nfqueue "github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/mdlayher/netlink"

	"golang.org/x/sys/unix"
)

func Htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}
func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	// 1. 创建 Raw Socket (ETH_P_ALL = 0x0300)
	//fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)

	// 使用 ETH_P_ALL (0x0003) 的转换结果
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(0x0003)))
	if err != nil {
		log.Fatalf("创建 Socket 失败: %v", err)
	}
	defer syscall.Close(fd)

	log.Println("DNS 采集器已启动 (强力匹配模式)...")

	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			continue
		}

		data := buf[:n]

		// 2. 关键：手动定位 IP 层
		// 监听 "any" 时，SLL 头部通常是 16 字节
		// 但有些接口可能是 14 字节 (Ethernet)。我们通过查找 IP 版本号特征来匹配
		var ipData []byte
		for i := 0; i < 32 && i < len(data); i++ {
			// IPv4 的版本号是 4，且首部长度通常是 20 字节 (0x45)
			if (data[i] & 0xf0) == 0x40 {
				ipData = data[i:]
				break
			}
		}

		if ipData == nil {
			continue
		}

		// 3. 使用 gopacket 解析 IP 层及以上
		packet := gopacket.NewPacket(ipData, layers.LayerTypeIPv4, gopacket.Default)

		// 过滤 UDP
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		udp, _ := udpLayer.(*layers.UDP)

		// 过滤 DNS 响应 (源端口 53)
		if udp.SrcPort != 53 {
			continue
		}

		// 解析 DNS
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}
		dnsMsg := dnsLayer.(*layers.DNS)

		if !dnsMsg.QR {
			continue
		}

		for _, answer := range dnsMsg.Answers {
			name := string(answer.Name)
			if answer.Type == layers.DNSTypeA {
				ip := answer.IP.String()
				dnsRecords.Add(ip, name)
				//fmt.Printf("捕获成功: %s -> %s\n", name, ip)
			}
		}
	}
}

func NetEvent(pid int, excludePorts *sync.Map) {

}

var mark int = 0x1aa

func RedirectAllTCP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map) {
	cleanupNftables("my_proxy_tcp")
	cleanupNftables("my_transparent_proxy")
	setupNftables("matchNet", uint16(proxyPort), mark)
}

func RedirectAllUDP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map, udpNat *udpProxy.UdpNat) {
	cleanupNftables("my_proxy_udp")
	var nfnum uint16 = 100
	setupNftablesUDPNat(uint16(proxyPort), mark, nfnum)

	config := nfqueue.Config{
		NfQueue:      nfnum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		return
	}
	//defer nf.Close()

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n",
			netlink.NoENOBUFS, err)
		return
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	fn := func(p nfqueue.Attribute) int {
		// 获取 ID 和 原始数据
		packetID := *p.PacketID
		packet := *p.Payload
		if len(packet) < 28 {
			nf.SetVerdict(packetID, nfqueue.NfAccept)
			return 0
		}

		srcIP := net.IP(packet[12:16])
		dstIP := net.IP(packet[16:20])
		srcPort := binary.BigEndian.Uint16(packet[20:22])
		dstPort := binary.BigEndian.Uint16(packet[22:24])

		// 逻辑：劫持或还原 (模仿你的 WinDivert 逻辑)
		if srcPort == proxyPort {
			// 处理代理回包
			vPort := dstPort
			addrInfo := udpNat.GetAddrFromVirtualPort(vPort)
			if addrInfo != nil {
				modified, err := modifyUDP(packet, addrInfo.DstIP, srcIP, addrInfo.DstPort, addrInfo.SrcPort)

				if err == nil {
					// 提交修改后的数据包
					nf.SetVerdictWithOption(packetID, nfqueue.NfAccept, nfqueue.WithAlteredPacket(modified))

					return 0
				}
			}
		} else if dstPort != proxyPort {
			// 劫持出站请求
			vPort := udpNat.GetVirtualPort(srcPort, dstIP, dstPort)
			//localIP := getLocalIP()
			modified, err := modifyUDP(packet, dstIP, srcIP, vPort, uint16(proxyPort))

			if err == nil {
				nf.SetVerdictWithOption(packetID, nfqueue.NfAccept, nfqueue.WithAlteredPacket(modified))
				return 0
			}
		}

		// 默认直接放行
		nf.SetVerdict(packetID, nfqueue.NfAccept)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(e error) int {
		fmt.Println(err)
		return -1
	})
	if err != nil {
		fmt.Println(err)
		return
	}

}
func modifyUDP(packet []byte, newSrcIP, newDstIP net.IP, newSrcPort, newDstPort uint16) ([]byte, error) {
	// 解析
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
	ipLayer := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	udpLayer := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)

	// 修改地址
	ipLayer.SrcIP = newSrcIP
	ipLayer.DstIP = newDstIP
	udpLayer.SrcPort = layers.UDPPort(newSrcPort) // gopacket 中端口类型通用
	udpLayer.DstPort = layers.UDPPort(newDstPort)

	// 重新打包并计算校验和
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true, // 核心：替代 WinDivert 的 CalcChecksums
		FixLengths:       true,
	}

	// UDP 校验和依赖 IP 伪头部
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	// 获取应用层数据
	var payload gopacket.Payload
	if app := pkt.ApplicationLayer(); app != nil {
		payload = gopacket.Payload(app.Payload())
	}

	err := gopacket.SerializeLayers(buf, opts, ipLayer, udpLayer, payload)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
func CloseNetEvent() {

}

func CloseWinDivert() {
	cleanupNftables("cleanupNftables")
	cleanupNftables("my_proxy_udp")
}
func GetMark() int {
	return mark
}
func SetMark(_mark int) {
	mark = mark
}

func cleanupNftables(name string) {
	//sudo nft delete table ip my_transparent_proxy
	c := &nftables.Conn{}
	// 1. 创建或清空表 (ip nat)
	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   name,
	})
	c.DelTable(table)
	c.Flush()
}

func setupNftables(setName string, proxyPort uint16, mark int) {

	/*
		sudo nft delete table ip my_transparent_proxy
		sudo nft add table ip my_transparent_proxy
		sudo nft 'add set ip my_transparent_proxy test { type ipv4_addr; flags interval,timeout; }'
		sudo nft 'add element ip my_transparent_proxy test { 0.0.0.0/0 timeout 1m }'
		sudo nft 'add chain ip my_transparent_proxy OUTPUT { type nat hook output priority -150; }'
		sudo nft 'insert rule ip my_transparent_proxy OUTPUT meta mark 0x1a accept'
		sudo nft 'add rule ip my_transparent_proxy OUTPUT ip daddr @test tcp dport 1-65535 redirect to :7080'
	*/

	/*
		ct state established   socket exists
	*/

	c := &nftables.Conn{}
	// 1. 创建或清空表 (ip nat)
	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "my_proxy_tcp",
	})

	// 2. 创建带有超时功能的集合
	// 只要 0.0.0.0/0 在这个集合里，转发就生效
	set := &nftables.Set{
		Table:      table,
		Name:       setName,
		KeyType:    nftables.TypeIPAddr, // IPv4 地址
		Interval:   true,                // 支持网段 (如 0.0.0.0/0)
		HasTimeout: true,                // 开启超时功能
	}
	if err := c.AddSet(set, nil); err != nil {
		log.Fatalf("创建 Set 失败: %v", err)
	}

	// 3. 创建 OUTPUT 链 (NAT 钩子)
	chain := c.AddChain(&nftables.Chain{
		Name:     "OUTPUT_PROXY",
		Table:    table,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	})

	markValue := uint32(mark) // 你的标记数值
	markBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(markBytes, markValue)

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: markBytes},
			&expr.Verdict{Kind: expr.VerdictAccept}, // 匹配就直接 Accept
		},
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
			// 匹配 ESTABLISHED (2) 和 RELATED (4) 状态
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           []byte{0x06, 0, 0, 0},
				Xor:            []byte{0, 0, 0, 0},
			},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
			&expr.Verdict{Kind: expr.VerdictAccept}, // 发现是老连接，直接放行
		},
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// 提取目的 IP 地址 (PayloadBaseNetworkHeader Offset 16 是 IPv4 daddr)
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			// 判断是否等于 127.0.0.1 (注意：IP地址在包中是大端序)
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{127, 0, 0, 1},
			},
			// 如果匹配，直接 Accept（放行，不再往下走 redirect 规则）
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	cgroupID, err := getCgroupID("/sys/fs/cgroup/no_proxy_group")
	if err != nil {
		log.Fatal(err)
	}
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Socket{Key: expr.SocketKeyCgroupv2},
			// 这里匹配 cgroup 的 path 或者 ID
			// 简单做法是直接在命令行执行一次：
			// nft add rule ip my_proxy_udp output socket cgroupv2 level 2 "proxy_bypass" accept
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     cgroupID, // 这需要你先从文件系统获取 cgroup 的 handle
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// 4. 添加规则：meta skmark != 0x1A && ip daddr @proxy_active_set redirect to :7080
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, proxyPort) // 端口也必须大端
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// 1. 匹配目的地 IP 集合 (ip daddr @test)
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Lookup{SetName: set.Name, SourceRegister: 1},

			// 2. 匹配 TCP 协议 (ip protocol tcp)
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 9, Len: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},

			// 3. 将端口放入寄存器并执行重定向
			&expr.Immediate{Register: 1, Data: portBytes},
			&expr.Redir{
				RegisterProtoMin: 1, // 对应手工的 redirect
			},
		},
	})
	// 提交更改到内核
	if err := c.Flush(); err != nil {
		log.Fatalf("提交 nftables 规则失败: %v", err)
	}
	//先手工添加一次
	addNetworkSet(c, set)
	// 5. 开启心跳：每 5 秒给 0.0.0.0/0 续期 10 秒
	go func() {
		ticker := time.NewTicker(7 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			addNetworkSet(c, set)
		}
	}()
}

func getCgroupID(path string) ([]byte, error) {
	// 1. 手动定义 FileHandle 头部大小 (linux/f_handle.h)
	// struct file_handle { unsigned int handle_bytes; int handle_type; };
	// 两个 int32 共 8 字节
	const sizeofFileHandle = 8

	// 准备缓冲区：头部(8字节) + 句柄数据(通常为8字节的inode)
	// 我们预留大一点防止溢出

	// 将路径转换为 C 风格字符串指针
	pathPtr, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}

	var mountID int32
	// 预留 handle 空间 (struct file_handle + 8 bytes data)
	handle := make([]byte, 8+64)
	var rawAtFdCwd int = unix.AT_FDCWD
	// 2. 执行系统调用，注意 AT_FDCWD 的转换
	_, _, errno := unix.Syscall6(
		unix.SYS_NAME_TO_HANDLE_AT,
		uintptr(rawAtFdCwd), // 修正点：int 强制中转
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&handle[0])),
		uintptr(unsafe.Pointer(&mountID)),
		0, 0,
	)

	// EOVERFLOW 是正常的，因为我们可能没提前告诉内核 handle 的大小，
	// 但内核依然会把 ID 填入 handle 剩下的字节中
	if errno != 0 && errno != unix.EOVERFLOW {
		return nil, fmt.Errorf("syscall failed with errno: %v", errno)
	}

	// 3. 提取 8 字节的 Cgroup ID
	// 跳过头部的 8 字节 (handle_bytes 和 handle_type)
	id := make([]byte, 8)
	copy(id, handle[sizeofFileHandle:sizeofFileHandle+8])

	return id, nil
}

/*添加网段到集合*/
func addNetworkSet(c *nftables.Conn, set *nftables.Set) error {
	//sudo nft 'add element ip my_transparent_proxy test { 0.0.0.0/0 timeout 1m }'
	element := []nftables.SetElement{
		{
			Key:         net.IPv4(0, 0, 0, 0).To4(),
			IntervalEnd: false,
			Timeout:     15 * time.Second,
		},
		{
			Key:         net.IPv4(255, 255, 255, 255).To4(),
			IntervalEnd: true,
		},
	}
	c.FlushSet(set)
	if err := c.SetAddElements(set, element); err != nil {
		log.Printf("续期失败: %v", err)
	}
	return c.Flush() // 必须 Flush 才会生效
}

func setupNftablesUDPNat(proxyPort uint16, excludeMark int, NFQNum uint16) {
	c := &nftables.Conn{}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "my_proxy_udp",
	})

	// 注意：NFQueue 处理包一般放在 filter/mangle，而不是 NAT 链
	chain := c.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityMangle,
	})

	markValue := uint32(excludeMark)
	markBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(markBytes, markValue)

	// 1. 匹配免死金牌 (Mark)，匹配就直接 Accept
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: markBytes},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// 3. 排除 127.0.0.1
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{127, 0, 0, 1}},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})

	// 4. 核心拦截：UDP + (可选集合) -> NFQueue
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// 必须是 UDP
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},

			// 排除 DNS 53
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0x00, 0x35}},

			// 进入队列
			&expr.Queue{Num: NFQNum, Flag: expr.QueueFlagBypass},
		},
	})

	if err := c.Flush(); err != nil {
		log.Fatalf("Flush 失败: %v", err)
	}
}
