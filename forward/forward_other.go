//go:build !windows
// +build !windows

package forward

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"
)

func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	// 1. 打开网络设备进行嗅探
	// "eth0" 替换为你实际的网卡名，或者用 "any" 监听所有网卡
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("无法打开网卡: %v", err)
	}
	defer handle.Close()

	// 2. 设置 BPF 过滤器
	// 仅入站 (需结合网卡方向)、来自 53 端口的 UDP
	// 注意：libpcap 的 inbound 过滤器取决于驱动支持，通常直接用 src port 53 即可
	filter := "udp and src port 53"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("设置过滤器失败: %v", err)
	}

	// 3. 开始解析
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 尝试解析 DNS 层
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer == nil {
			continue
		}

		dnsMsg := dnsLayer.(*layers.DNS)

		// 检查是否是响应包
		if !dnsMsg.QR {
			continue
		}

		for _, answer := range dnsMsg.Answers {
			name := string(answer.Name)

			// 提取 A 记录 (IPv4)
			if answer.Type == layers.DNSTypeA {
				ip := answer.IP.String()
				dnsRecords.Add(ip, name)
				log.Printf("[DNS A] %s -> %s", name, ip)
			}
			// 提取 AAAA 记录 (IPv6)
			if answer.Type == layers.DNSTypeAAAA {
				//ip := answer.IP.String()
				// dnsRecords.Add(ip, name)
			}
		}
	}
}

func NetEvent(pid int, excludePorts *sync.Map) {

}

var mark int = 0x1aa

func RedirectAllTCP(proxyPort uint16, excludePorts *sync.Map, originalPorts *sync.Map) {
	cleanupNftables()
	setupNftables("matchNet", uint16(proxyPort), mark)
}

func CloseNetEvent() {

}

func CloseWinDivert() {
	cleanupNftables()
}
func GetMark() int {
	return mark
}
func SetMark(_mark int) {
	mark = mark
}

func cleanupNftables() {
	//sudo nft delete table ip my_transparent_proxy
	c := &nftables.Conn{}
	// 1. 创建或清空表 (ip nat)
	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "my_transparent_proxy",
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
		Name:   "my_transparent_proxy",
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
