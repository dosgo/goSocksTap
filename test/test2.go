package main

import (
	"fmt"

	"github.com/dosgo/goSocksTap/comm"
)

func main() {

	// 假设你从公开资源下载了这些文件
	//https://raw.githubusercontent.com/gaoyifan/china-operator-ip/refs/heads/ip-lists/china6.txt
	//https://raw.githubusercontent.com/gaoyifan/china-operator-ip/refs/heads/ip-lists/china4.txt

	testIPs := []string{"114.114.114.114", "8.8.8.8", "240e:e1:8100:28::2"}
	for _, ipStr := range testIPs {
		isChina := comm.IsChinaMainlandIP(ipStr)
		fmt.Printf("IP: %-20s 是否中国: %v\n", ipStr, isChina)
	}
}
