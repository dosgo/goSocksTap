package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dosgo/goSocksTap/socksTap"
)

func main() {
	socksTap := socksTap.NewSocksTap(1095, "socks5://192.168.94.134:10808", 1, true)
	socksTap.Start()
	defer socksTap.Close()

	sigCh := make(chan os.Signal, 1)
	// 3. 注册信号
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	fmt.Println("服务已启动...")

	sig := <-sigCh
	fmt.Printf("\n接收到信号: %v，正在执行清理...\n", sig)

}
