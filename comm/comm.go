package comm

import (
	"net"
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
