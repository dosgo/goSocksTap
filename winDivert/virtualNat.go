//go:build windows
// +build windows

package winDivert

import (
	"fmt"
	"net"
	"sync"
	"time"
)

var udpFakePort uint16 = 20000
var fakeTable sync.Map
var reverseTable sync.Map
var portMu sync.Mutex // 保证自增和双向存储的原子性

// 用来记录: fakePort -> {原始源端口, 原始目标IP, 原始目标端口}

type udpSession struct {
	SrcPort  uint16
	DstIP    net.IP
	DstPort  uint16
	lastTime int64
}

func init() {
	go Clear()
}
func GetVirtualPort(srcPort uint16, dstIP net.IP, dstPort uint16) uint16 {
	portMu.Lock()
	defer portMu.Unlock()
	// 构造唯一 Key
	key := fmt.Sprintf("%d-%s-%d", srcPort, dstIP.String(), dstPort)

	// 1. 先检查是否已经分配过
	if val, ok := reverseTable.Load(key); ok {
		GetAddrFromVirtualPort(val.(uint16))
		return val.(uint16)
	}

	// 简单粗暴：直接自增，循环使用
	udpFakePort++
	if udpFakePort > 60000 {
		udpFakePort = 20000
	}

	p := udpFakePort
	fakeTable.Store(p, &udpSession{srcPort, dstIP, dstPort, time.Now().Unix()})
	reverseTable.Store(key, p)
	return p
}

func GetAddrFromVirtualPort(fakePort uint16) *udpSession {
	if val, ok := fakeTable.Load(fakePort); ok {
		session := val.(*udpSession)
		session.lastTime = time.Now().Unix()
		return session
	}
	return nil
}

func Clear() {
	for {

		fakeTable.Range(func(key, value interface{}) bool {
			session := value.(*udpSession)
			if time.Now().Unix()-session.lastTime > 60 {
				fakeTable.Delete(key)
				reverseTable.Delete(fmt.Sprintf("%d-%s-%d", session.SrcPort, session.DstIP.String(), session.DstPort))
			}
			return true
		})
		time.Sleep(time.Second * 5)
	}
}
