package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	// 1. 创建强制 HTTP/3 的客户端
	client := &http.Client{
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				NextProtos: []string{"h3"}, // 只允许 HTTP/3
			},
		},
		Timeout: 10 * time.Second,
	}

	// 2. 测试网址
	url := "https://http3.is/"

	// 3. 发送请求
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("❌ 错误: %v\n", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	// 4. 显示结果
	fmt.Printf("🌐 强制 HTTP/3 测试\n")
	fmt.Printf("   网站: %s\n", url)
	fmt.Printf("   协议: %s\n", resp.Proto)
	fmt.Printf("   状态: %d\n", resp.StatusCode)
	fmt.Printf(resp.Request.RemoteAddr)
	fmt.Printf("   内容预览: %.100s...\n", body)
	if resp.Proto == "HTTP/3.0" {
		fmt.Println("   ✅ 成功: 使用 HTTP/3 协议")
	}
}
