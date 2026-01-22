package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

const (
	socks5Version = 0x05
	authNone      = 0x00
	cmdConnect    = 0x01
	atypIPv4      = 0x01
	atypDomain    = 0x03
	atypIPv6      = 0x04
)

func main() {
	// 监听端口
	listener, err := net.Listen("tcp", ":10801")
	if err != nil {
		log.Fatal("无法启动代理服务器:", err)
	}
	defer listener.Close()

	fmt.Println("SOCKS5 代理服务器运行在 :10801")

	for {
		client, err := listener.Accept()
		if err != nil {
			log.Println("接受客户端连接失败:", err)
			continue
		}
		go handleClient(client)
	}
}

func handleClient(client net.Conn) {
	defer client.Close()

	// 握手阶段
	if err := handshake(client); err != nil {
		log.Println("握手失败:", err)
		return
	}

	// 解析请求
	target, err := parseRequest(client)
	if err != nil {
		log.Println("解析请求失败:", err)
		return
	}

	// 连接目标服务器
	targetConn, err := net.Dial("tcp", target)
	if err != nil {
		log.Println("连接目标服务器失败:", err)
		sendReply(client, 0x04) // 主机不可达
		return
	}
	defer targetConn.Close()

	// 发送成功响应
	if err := sendReply(client, 0x00); err != nil {
		log.Println("发送响应失败:", err)
		return
	}

	// 双向转发数据
	go func() {
		io.Copy(targetConn, client)
		targetConn.Close()
	}()
	io.Copy(client, targetConn)
}

// 握手阶段
func handshake(client net.Conn) error {
	buf := make([]byte, 256)

	// 读取客户端问候
	n, err := io.ReadAtLeast(client, buf, 2)
	if err != nil {
		return err
	}

	if buf[0] != socks5Version {
		return errors.New("不支持的 SOCKS 版本")
	}

	// 检查支持的认证方法
	nmethods := int(buf[1])
	if n != 2+nmethods {
		return errors.New("认证方法数据不完整")
	}

	// 检查是否支持无认证
	hasNoAuth := false
	for i := 0; i < nmethods; i++ {
		if buf[2+i] == authNone {
			hasNoAuth = true
			break
		}
	}

	if !hasNoAuth {
		client.Write([]byte{socks5Version, 0xFF})
		return errors.New("没有支持的认证方法")
	}

	// 响应：选择无认证
	_, err = client.Write([]byte{socks5Version, authNone})
	return err
}

// 解析请求
func parseRequest(client net.Conn) (string, error) {
	buf := make([]byte, 256)

	// 读取请求头
	n, err := io.ReadAtLeast(client, buf, 5)
	if err != nil {
		return "", err
	}

	if buf[0] != socks5Version {
		return "", errors.New("不支持的 SOCKS 版本")
	}

	if buf[1] != cmdConnect {
		return "", errors.New("不支持的 SOCKS 命令")
	}

	var host string
	var port uint16

	switch buf[3] {
	case atypIPv4:
		if n < 10 {
			return "", errors.New("IPv4 地址数据不完整")
		}
		host = net.IPv4(buf[4], buf[5], buf[6], buf[7]).String()
		port = binary.BigEndian.Uint16(buf[8:10])

	case atypDomain:
		domainLen := int(buf[4])
		if n < 7+domainLen {
			return "", errors.New("域名数据不完整")
		}
		host = string(buf[5 : 5+domainLen])
		port = binary.BigEndian.Uint16(buf[5+domainLen : 7+domainLen])

	case atypIPv6:
		if n < 22 {
			return "", errors.New("IPv6 地址数据不完整")
		}
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])

	default:
		return "", errors.New("不支持的地址类型")
	}

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// 发送响应
func sendReply(client net.Conn, reply byte) error {
	// 简单响应：成功，绑定到 0.0.0.0:0
	resp := []byte{
		socks5Version,
		reply,
		0x00, // 保留
		atypIPv4,
		0x00, 0x00, 0x00, 0x00, // IP地址
		0x00, 0x00, // 端口
	}
	_, err := client.Write(resp)
	return err
}
