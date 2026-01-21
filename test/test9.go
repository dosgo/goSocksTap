package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

var (
	proxyPort int = 7080
	// 存储映射关系：源端口 -> 原始目标地址
	mark int = 0x1A
)

func main() {
	// 1. 设置 iptables 规则 (只拦截 TCP，排除本进程)
	// 建议通过当前用户 UID 过滤，防止死循环

	// 规则：将所有出站 TCP 流量（除了本用户发出的）导向 NFQUEUE 0
	//	setupIptables(mark, proxyPort)
	//defer cleanupIptables(mark, proxyPort)
	cleanupNftables()
	setupNftables("test", uint16(proxyPort), mark)
	// 2. 启动本地监听服务器 (透明代理逻辑)
	go startLocalRelay()

	// 阻塞直到接收退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("Linux 透明代理已启动 ...")
	<-sigChan
}

// startLocalRelay 处理被重定向到 7080 的连接
func startLocalRelay() {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", proxyPort))
	if err != nil {
		log.Fatalf("Listen failed: %v", err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()

			targetStr, err := getOriginalDst(c.(*net.TCPConn))
			fmt.Println(targetStr)
			// 连接真正的目标
			targetConn, err := dialer.Dial("tcp", targetStr)
			if err != nil {
				return
			}
			defer targetConn.Close()

			// 双向转发
			go func() { _, _ = io.Copy(targetConn, c) }()
			_, _ = io.Copy(c, targetConn)
		}(conn)
	}
}

var dialer = &net.Dialer{
	Timeout: 5 * time.Second,
	Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			// 给代理发出的包打上 0x1A 标记，避免被 iptables 再次拦截
			err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
			if err != nil {
				log.Printf("设置 SO_MARK 失败: %v", err)
			}
		})
	},
}

// Iptables 管理逻辑
func setupIptables(mark int, proxyPort int) {
	// 1. 在 nat 表中，将非标记流量重定向到代理端口
	cmd := fmt.Sprintf("iptables -t nat -A OUTPUT -p tcp -m mark ! --mark 0x%x -j REDIRECT --to-ports %d", mark, proxyPort)
	fmt.Printf("cmd:%s\r\n", cmd)
	runCmd(cmd)
}
func cleanupIptables(mark int, qNum int) {
	log.Println("正在清理 iptables 规则...")
	cmd := fmt.Sprintf("iptables -t nat -D OUTPUT -p tcp -m mark ! --mark 0x%x -j REDIRECT --to-ports %d", mark, proxyPort)
	runCmd(cmd)
}

func runCmd(s string) {
	_ = exec.Command("sh", "-c", s).Run()
}

func getOriginalDst(conn net.Conn) (string, error) {
	tcpConn := conn.(*net.TCPConn)
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return "", err
	}

	var addr string
	var controlErr error
	err = raw.Control(func(fd uintptr) {
		// 获取 REDIRECT 之前的原始目的地
		originalAddr, err := unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, unix.SO_ORIGINAL_DST) // 80 = SO_ORIGINAL_DST
		if err != nil {
			controlErr = err
			return
		}
		// 解析 originalAddr 得到 IP 和端口...
		ip := net.IPv4(
			originalAddr.Multiaddr[4],
			originalAddr.Multiaddr[5],
			originalAddr.Multiaddr[6],
			originalAddr.Multiaddr[7],
		)
		port := binary.BigEndian.Uint16(originalAddr.Multiaddr[2:4])
		addr = fmt.Sprintf("%s:%d", ip.String(), port)
	})

	if controlErr != nil {
		return "", controlErr
	}
	return addr, err
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
		sudo nft add rule ip my_table my_chain ct state established,related accept

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
