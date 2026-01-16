package main

import (
	"fmt"
	"net"

	"github.com/dosgo/goSocksTap/comm/iptools"
)

func main() {
	matcher := iptools.NewChinaIPMatcher()

	// 假设你从公开资源下载了这些文件
	//https://raw.githubusercontent.com/gaoyifan/china-operator-ip/refs/heads/ip-lists/china6.txt
	//https://raw.githubusercontent.com/gaoyifan/china-operator-ip/refs/heads/ip-lists/china4.txt
	err := matcher.LoadFromFiles("china.txt", "china6.txt")
	if err != nil {
		fmt.Printf("加载失败: %v\n", err)
		return
	}

	testIPs := []string{"114.114.114.114", "8.8.8.8", "240e:e1:8100:28::2"}
	for _, ipStr := range testIPs {
		ip := net.ParseIP(ipStr)
		isChina := matcher.IsChinaIP(ip)
		fmt.Printf("IP: %-20s 是否中国: %v\n", ipStr, isChina)
	}
}
