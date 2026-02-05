package comm

import "sync/atomic"

type PortBitmap struct {
	data [1024]uint64
}

func (b *PortBitmap) Set(port uint16) {
	index := port / 64
	bit := uint64(1) << (port % 64)
	// 原子地执行 b.data[index] |= bit
	atomic.OrUint64(&b.data[index], bit)
}

func (b *PortBitmap) Has(port uint16) bool {
	index := port / 64
	bit := uint64(1) << (port % 64)
	return (atomic.LoadUint64(&b.data[index]) & bit) != 0
}
func (b *PortBitmap) Clear() {
	for i := 0; i < len(b.data); i++ {
		atomic.StoreUint64(&b.data[i], 0)
	}
}
func (b *PortBitmap) Delete(port uint16) {
	index := port / 64
	bit := uint64(1) << (port % 64)
	// 通过与非运算清除特定位
	atomic.AndUint64(&b.data[index], ^bit)
}
