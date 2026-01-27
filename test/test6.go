package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	socks51 "github.com/wzshiming/socks5"
)

func main() {
	socksServer()
	// 设置信号处理
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	// 等待停止信号
	<-sig

	log.Println("服务器已停止")
}

func socksServer() {
	socks51.NewServer().ListenAndServe("tcp", "0.0.0.0:10801")
}
