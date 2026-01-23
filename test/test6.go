package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/txthinking/socks5"
)

func main() {
	// 创建 SOCKS5 服务器，监听 1080 端口
	server, err := socks5.NewClassicServer("0.0.0.0:10801", "", "", "", 0, 60)

	if err != nil {
		log.Fatal(err)
	}

	// 启动服务器
	log.Println("SOCKS5 服务器已启动")
	log.Println("监听地址: 0..0.0.0:10801")
	log.Println("支持协议: TCP 和 UDP")
	log.Println("认证: 无")
	log.Println("按 Ctrl+C 停止服务器")

	// 设置信号处理
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// 启动服务器
	go func() {
		if err := server.ListenAndServe(nil); err != nil {
			log.Fatal(err)
		}
	}()

	// 等待停止信号
	<-sig

	// 停止服务器
	server.Shutdown()
	log.Println("服务器已停止")
}
