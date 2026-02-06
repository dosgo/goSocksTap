package comm

import "sync/atomic"

type PortNAT struct {
	// 使用 [65536]uint32 以支持 atomic 操作（Go 不支持 atomic.Uint16）
	table [65536]uint32
}

// NewPortNAT 创建新的 NAT 表
func NewPortNAT() *PortNAT {
	return &PortNAT{}
}

// Set 设置 srcPort 到 dstPort 的映射
func (n *PortNAT) Set(srcPort, dstPort uint16) {
	if dstPort == 0 {
		panic("PortNAT: dstPort=0 is reserved for 'no mapping'")
	}
	atomic.StoreUint32(&n.table[srcPort], uint32(dstPort))
}

// Get 获取 srcPort 对应的 dstPort
// 返回 (dstPort, ok)，若未映射则 ok = false
func (n *PortNAT) Get(srcPort uint16) (dstPort uint16, ok bool) {
	val := atomic.LoadUint32(&n.table[srcPort])
	if val == 0 {
		return 0, false
	}
	return uint16(val), true
}

// Delete 删除映射（设为 0）
func (n *PortNAT) Delete(srcPort uint16) {
	atomic.StoreUint32(&n.table[srcPort], 0)
}
