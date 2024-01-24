//go:build windows
// +build windows

package winDivert

import (
	_ "embed"
	"encoding/binary"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/imgk/divert-go"
)

var winDivert *divert.Handle
var winDivertRun = false

var divertDll = "WinDivert.dll"
var divertSys = "WinDivert32.sys"

func dllInit(_divertDll string) {
	_, err := os.Stat(_divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", _divertDll)
	}
}

/*windows转发*/
func RedirectDNS(dnsAddr string, _port string, sendStartPort int, sendEndPort int) {
	var err error
	_, err = os.Stat(divertDll)
	if err != nil {
		log.Printf("not found :%s\r\n", divertDll)
		return
	}
	winDivertRun = true
	var filter = "outbound and !loopback and !impostor and udp.DstPort=53"

	for i := sendStartPort; i <= sendEndPort; i++ {
		filter = filter + " and udp.SrcPort!=" + strconv.Itoa(i)
	}

	winDivert, err = divert.Open(filter, divert.LayerNetwork, divert.PriorityDefault, divert.FlagDefault)
	if err != nil {
		log.Printf("winDivert open failed: %v\r\n", err)
		return
	}

	rawbuf := make([]byte, 1500)
	var dnsRecvBuf []byte = make([]byte, 1500)
	var recvBuf []byte = make([]byte, 1500)
	addr := divert.Address{}
	var dnsConn net.Conn
	dnsConn, _ = net.DialTimeout("udp", dnsAddr+":"+_port, time.Second*15)
	var udpsize=0;
	var packetsize int=0;
	var ipheadlen int
	var recvLen uint
	var conRecvLen int
	var udpheadlen = 8
	for winDivertRun {
		if winDivert == nil {
			continue
		}
		recvLen, err = winDivert.Recv(recvBuf, &addr)
		if err != nil {
			log.Println(1, err)
			continue
		}
		ipv6 := recvBuf[0]>>4 == 6
		if ipv6 {
			ipheadlen = 40
		} else {
			ipheadlen = int(recvBuf[0]&0xF) * 4
		}
		dnsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		dnsConn.Write(recvBuf[ipheadlen+udpheadlen : recvLen])
		dnsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		conRecvLen, err = dnsConn.Read(dnsRecvBuf)
		if err == nil {
			udpsize = conRecvLen +udpheadlen
			if ipv6 {
				copy(rawbuf, []byte{96, 12, 19, 68, 0, 98, 17, 128})
				packetsize = 40 + udpsize
				binary.BigEndian.PutUint16(rawbuf[4:], uint16(udpsize))
				copy(rawbuf[8:], recvBuf[24:40])
				copy(rawbuf[24:], recvBuf[8:24])
				copy(rawbuf[ipheadlen:], recvBuf[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[ipheadlen+2:], recvBuf[ipheadlen:ipheadlen+2])
			} else {
				copy(rawbuf, []byte{69, 0, 1, 32, 141, 152, 64, 0, 64, 17, 150, 46})
				packetsize = 20 + udpsize
				binary.BigEndian.PutUint16(rawbuf[2:], uint16(packetsize))
				copy(rawbuf[12:], recvBuf[16:20])
				copy(rawbuf[16:], recvBuf[12:16])
				copy(rawbuf[20:], recvBuf[ipheadlen+2:ipheadlen+4])
				copy(rawbuf[22:], recvBuf[ipheadlen:ipheadlen+2])
				ipheadlen = 20
			}

			binary.BigEndian.PutUint16(rawbuf[ipheadlen+4:], uint16(udpsize))
			copy(rawbuf[ipheadlen+udpheadlen:], dnsRecvBuf[:conRecvLen])
			divert.CalcChecksums( rawbuf[:packetsize], &addr, 0)
			_, err = winDivert.Send( rawbuf[:packetsize], &addr)
			if err != nil {
				log.Println(1, err)
				return
			}
		} else {
			dnsConn.Close()
			dnsConn, _ = net.DialTimeout("udp", dnsAddr+":"+_port, time.Second*15)
		}
	}
	if dnsConn != nil {
		dnsConn.Close()
	}
}

func CloseWinDivert() {
	winDivertRun = false
	if winDivert != nil {
		winDivert.Close()
	}
}
