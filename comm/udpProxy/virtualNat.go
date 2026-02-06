package udpProxy

import (
	"net/netip"
	"sync"
	"time"
)

// 用来记录: fakePort -> {原始源端口, 原始目标IP, 原始目标端口}

type UdpSession struct {
	SrcPort  uint16
	DstAddr  netip.AddrPort
	lastTime int64
}
type sessionKey struct {
	srcPort uint16
	dstAddr netip.AddrPort
}

type UdpNat struct {
	udpFakePort  uint16
	fakeTable    *sync.Map
	reverseTable *sync.Map
	portMu       sync.Mutex // 保证自增和双向存储的原子性
	run          bool
}

func NewUdpNat() *UdpNat {
	info := &UdpNat{
		udpFakePort:  20000,
		run:          true,
		fakeTable:    &sync.Map{},
		reverseTable: &sync.Map{},
	}
	go info.clear()
	return info
}
func (udpNat *UdpNat) GetVirtualPort(srcPort uint16, dstIP netip.Addr, dstPort uint16) uint16 {
	udpNat.portMu.Lock()
	defer udpNat.portMu.Unlock()
	// 构造唯一 Key
	//key := fmt.Sprintf("%d-%s-%d", srcPort, dstIP.String(), dstPort)
	key := sessionKey{srcPort, netip.AddrPortFrom(dstIP, dstPort)}
	// 1. 先检查是否已经分配过
	if val, ok := udpNat.reverseTable.Load(key); ok {
		udpNat.GetAddrFromVirtualPort(val.(uint16))
		return val.(uint16)
	}

	// 简单粗暴：直接自增，循环使用
	udpNat.udpFakePort++
	if udpNat.udpFakePort > 60000 {
		udpNat.udpFakePort = 20000
	}

	p := udpNat.udpFakePort
	udpNat.fakeTable.Store(p, &UdpSession{srcPort, netip.AddrPortFrom(dstIP, dstPort), time.Now().Unix()})
	udpNat.reverseTable.Store(key, p)
	return p
}

func (udpNat *UdpNat) GetAddrFromVirtualPort(fakePort uint16) *UdpSession {
	if val, ok := udpNat.fakeTable.Load(fakePort); ok {
		session := val.(*UdpSession)
		session.lastTime = time.Now().Unix()
		return session
	}
	return nil
}

func (udpNat *UdpNat) clear() {
	for udpNat.run {
		udpNat.fakeTable.Range(func(key, value interface{}) bool {
			session := value.(*UdpSession)
			if time.Now().Unix()-session.lastTime > 60 {
				udpNat.fakeTable.Delete(key)
				udpNat.reverseTable.Delete(sessionKey{session.SrcPort, session.DstAddr})
			}
			return true
		})
		time.Sleep(time.Second * 30)
	}
}
