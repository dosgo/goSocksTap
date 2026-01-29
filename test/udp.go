package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	// 阿里云 NTP 服务器地址
	remoteAddr := "ntp.aliyun.com:123"

	// 1. 建立 UDP 连接
	// 在标准库中，DialUDP 不会产生实际流量，只是初始化一个 UDP 结构
	conn, err := net.DialTimeout("udp", remoteAddr, 5*time.Second)
	if err != nil {
		fmt.Printf("无法连接服务器: %v\n", err)
		return
	}
	defer conn.Close()

	// 2. 构造标准的 NTP 请求包 (RFC 5905)
	// NTP 包长度为 48 字节
	msg := make([]byte, 48)
	// 第一个字节设置：LI = 0, VN = 3 (版本3), Mode = 3 (客户端)
	// 二进制为 00 011 011 -> 0x1B
	msg[0] = 0x1B

	fmt.Printf("正在向 %s 发送 NTP 查询...\n", remoteAddr)

	// 3. 发送数据
	// 这行执行时，WinDivert 会拦截此包，你应该能在你的拦截程序里看到它
	_, err = conn.Write(msg)
	if err != nil {
		fmt.Printf("发送失败: %v\n", err)
		return
	}

	// 4. 设置读取超时并接收回包
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	answer := make([]byte, 48)
	n, err := conn.Read(answer)
	if err != nil {
		fmt.Printf("接收回包失败 (检查你的转发逻辑是否通畅): %v\n", err)
		return
	}

	// 5. 解析简单的时间信息 (NTP 时间从 1900 年开始计算)
	// 秒数位于报文的 40-43 字节
	if n >= 48 {
		seconds := uint32(answer[40])<<24 | uint32(answer[41])<<16 | uint32(answer[42])<<8 | uint32(answer[43])
		const ntpEpochOffset = 2208988800 // 1900年到1970年的秒数差
		unixTime := time.Unix(int64(seconds-ntpEpochOffset), 0)
		fmt.Printf("成功收到阿里云回包！\n当前网络时间: %v\n", unixTime)
	}
}
