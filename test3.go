package main

import (
	"github.com/dosgo/goSocksTap/winDivert"
)

func main() {
	winDivert.RedirectData(1088)
}
