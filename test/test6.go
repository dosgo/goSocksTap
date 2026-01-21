package main

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 2. 使用该 Transport 创建自定义 Client
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://github.com/dosgo/castX")
	if err != nil {
		log.Printf("err:%+v\r\n", err)
		return
	}
	io.Copy(os.Stdout, resp.Body)
	resp.Body.Close()

}
