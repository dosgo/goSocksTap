package comm

import (
	"net"
	"net/netip"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

func IsPublicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if !ip.IsPrivate() {
		return true
	}
	return false
}

func ParsePacketInfoFast(packet []byte) (net.IP, uint16, net.IP, uint16) {
	// 1. 基础长度检查
	if len(packet) < 20 {
		return nil, 0, nil, 0
	}

	// 2. 检查是否为 IPv4
	if (packet[0] >> 4) != 4 {
		return nil, 0, nil, 0
	}

	// 3. 重要：拷贝 IP 字节，防止后续修改 packet 时影响变量值
	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	copy(srcIP, packet[12:16])
	copy(dstIP, packet[16:20])

	// 4. 动态计算 TCP 偏移量
	ihl := int(packet[0]&0x0F) * 4

	// 5. 再次安全检查：确保 packet 长度足够读取 TCP 端口 (ihl + 4 字节)
	if len(packet) < ihl+4 {
		return nil, 0, nil, 0
	}

	srcPort := uint16(packet[ihl])<<8 | uint16(packet[ihl+1])
	dstPort := uint16(packet[ihl+2])<<8 | uint16(packet[ihl+3])

	return srcIP, srcPort, dstIP, dstPort
}

func ModifyPacketFast(packet []byte, newSrcIP net.IP, newSrcPort uint16, newDstIP net.IP, newDstPort uint16) {
	// 1. 修改 IP (IPv4 头部固定 12-19 字节)
	copy(packet[12:16], newSrcIP.To4())
	copy(packet[16:20], newDstIP.To4())

	// 2. 动态计算 TCP 偏移量 (IHL)
	ihl := int(packet[0]&0x0F) * 4

	// 3. 修改端口 (基于 ihl 偏移)
	packet[ihl] = uint8(newSrcPort >> 8)
	packet[ihl+1] = uint8(newSrcPort)
	packet[ihl+2] = uint8(newDstPort >> 8)
	packet[ihl+3] = uint8(newDstPort)

}

var geoCache = expirable.NewLRU[string, bool](2000, nil, time.Minute*15)
var proxyMode = 0

func SetProxyMode(mode int) {
	proxyMode = mode
}
func IsProxyRequiredFast(ipStr string) bool {
	//如果是全局代理lian,则全部代理
	if proxyMode == 0 {
		return true
	}
	//局域网ip也不代理
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	// IsPrivate 涵盖了 RFC 1918 (IPv4) 和 RFC 4193 (IPv6)
	if addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return false
	}

	// 1. 检查缓存 (Fast Path)
	if isChina, ok := geoCache.Get(ipStr); ok {
		return !isChina // 如果是中国 IP，则不需要代理
	}

	// 2. 执行真正的查询 (Slow Path)
	isChina := IsChinaMainlandIP(ipStr)

	// 3. 写入缓存
	geoCache.Add(ipStr, isChina)

	return !isChina
}
