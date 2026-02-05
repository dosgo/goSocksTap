//go:build !windows
// +build !windows

package forward

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dosgo/goSocksTap/comm"
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
				//log.Printf("捕获成功: %s -> %s\n", name, ip)
			}
		}
	}
}

func ForceRestartWithGID(pid int) (int, error) {

	// 1. 获取原进程的 Uid、路径、参数、环境变量、工作目录
	status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	var originalUid uint32
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fmt.Sscanf(line, "Uid:\t%d", &originalUid)
			break
		}
	}

	exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))

	rawArgs, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	args := strings.Split(string(rawArgs), "\x00")
	if len(args) > 0 && args[len(args)-1] == "" {
		args = args[:len(args)-1]
	}

	rawEnv, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	env := strings.Split(string(rawEnv), "\x00")

	// 2. 杀掉旧进程
	proc, _ := os.FindProcess(pid)
	_ = proc.Signal(syscall.SIGKILL) // 暴力一点，确保杀掉
	time.Sleep(time.Millisecond * 100)
	// 3. 构造新进程并注入 GID
	cmd := exec.Command(exe, args[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    originalUid, // 保持原 UID
			Gid:    uint32(gid), // 强制改 GID
			Groups: []uint32{uint32(gid)},
		},
		Setsid: true, // 让它在后台独立运行
	}

	log.Printf("[*] 正在重启 PID %d: %s (UID: %d, GID: %d)\n", pid, exe, originalUid, gid)
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("启动新进程失败: %v", err)
	}
	// 获取新生成的 PID
	newPid := cmd.Process.Pid

	// 必须释放资源：因为 Setsid=true，新进程已独立，如果不 Release 会产生僵尸记录
	cmd.Process.Release()
	return newPid, nil
}

var mark int = 0x1aa
var gid uint32 = 2000

func RedirectAllTCP(proxyPort uint16, excludePorts *comm.PortBitmap, originalPorts *sync.Map) {
	cleanupNftables("my_proxy_tcp")
	cleanupNftables("my_transparent_proxy")
	setupNftables("matchNet", uint16(proxyPort), mark)
}

func RedirectAllUDP(proxyPort uint16, excludePorts *comm.PortBitmap, originalPorts *sync.Map, udpNat *udpProxy.UdpNat) {
	cleanupNftables("my_proxy_udp")
	var nfnum uint16 = 100
	setupNftablesUDPNat(uint16(proxyPort), mark, nfnum)

	config := nfqueue.Config{
		NfQueue:      nfnum,
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFFFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		log.Println("could not open nfqueue socket:", err)
		return
	}

	// Avoid receiving ENOBUFS errors.
	if err := nf.SetOption(netlink.NoENOBUFS, true); err != nil {
		log.Printf("failed to set netlink option %v: %v\n",
			netlink.NoENOBUFS, err)
		return
	}

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
	err = nf.RegisterWithErrorFunc(context.Background(), fn, func(e error) int {
		log.Println(err)
		return -1
	})
	if err != nil {
		log.Println(err)
		return
	}

}
func modifyUDP(packet []byte, newSrcIP, newDstIP net.IP, newSrcPort, newDstPort uint16) ([]byte, error) {
	// 解析
	pkt := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.NoCopy)
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

func Stop() {
	cleanupNftables("my_proxy_tcp")
	cleanupNftables("my_proxy_udp")
}
func GetMark() int {
	return mark
}
func SetMark(_mark int) {
	mark = mark
}
func GetGid() uint32 {
	return gid
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

	gidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(gidBytes, gid)

	// --- 核心修改：匹配 GID 拦截/放行逻辑 ---
	// 1. 匹配目标 GID (比如 2000)，匹配就直接 Accept (放行，不进队列)
	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			// 读取数据包对应的 Socket GID 到寄存器 1
			&expr.Meta{Key: expr.MetaKeySKGID, Register: 1},
			// 比较寄存器 1 是否等于我们注入的 GID
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: gidBytes},
			// 如果相等，执行 Accept
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
func CheckUpdate(pid int, excludePorts *comm.PortBitmap, udpExcludePorts *comm.PortBitmap) {

}
