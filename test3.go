package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/dosgo/goSocksTap/winDivert"
)

func main() {
	winDivert.RedirectTCPNat(1088, "127.0.0.1", true)
	fmt.Print("按任意键继续...")
	bufio.NewReader(os.Stdin).ReadRune()
}
