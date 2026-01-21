//go:build !windows
// +build !windows

package forward

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sys/unix"
)

func CollectDNSRecords(dnsRecords *expirable.LRU[string, string]) {
	// 1. 创建 Raw Socket (ETH_P_ALL = 0x0300)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, 0x0300)
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
				fmt.Printf("捕获成功: %s -> %s\n", name, ip)
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
