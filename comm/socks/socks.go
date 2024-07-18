package socks

import (
	"bytes"
	"encoding/binary"
	"log"

	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

/*socks 5 udp header*/
func UdpHeadDecode(data []byte) (*net.UDPAddr, int, error) {

	/*
	   +----+------+------+----------+----------+----------+
	   |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	   +----+------+------+----------+----------+----------+
	   |  2 |   1  |   1  | Variable |     2    | Variable |
	   +----+------+------+----------+----------+----------+
	*/
	if data[2] != 0x00 {
		return nil, 0, errors.New("WARN: FRAG do not support")
	}

	var dstAddr *net.UDPAddr
	var dataStart = 0
	switch data[3] {
	case 0x01: //ipv4
		dstAddr = &net.UDPAddr{
			IP:   net.IPv4(data[4], data[5], data[6], data[7]),
			Port: int(data[8])*256 + int(data[9]),
		}
		dataStart = 10
		break
	case 0x03: //domain
		domainLen := int(data[4])
		domain := string(data[5 : 5+domainLen])
		ipAddr, err := net.ResolveIPAddr("ip", domain)
		if err != nil {
			return nil, 0, errors.New(fmt.Sprintf("Error -> domain %s dns query err:%v\n", domain, err))
		}
		dstAddr = &net.UDPAddr{
			IP:   ipAddr.IP,
			Port: int(data[5+domainLen])*256 + int(data[6+domainLen]),
		}
		dataStart = 6 + domainLen
		break
	default:
		return nil, 0, errors.New(fmt.Sprintf(" WARN: ATYP %v do not support.\n", data[3]))

	}
	return dstAddr, dataStart, nil
}

func UdpHeadEncode(addr *net.UDPAddr) []byte {
	bindMsg := []byte{0x05, 0x00, 0x00, 0x01}
	buffer := bytes.NewBuffer(bindMsg)
	binary.Write(buffer, binary.BigEndian, addr.IP.To4())
	binary.Write(buffer, binary.BigEndian, uint16(addr.Port))
	return buffer.Bytes()
}

/* udp req res*/
func UdpProxyRes(clientConn net.Conn, udpAddr *net.UDPAddr) error {
	if udpAddr == nil {
		return nil
	}
	log.Printf("req Udp addr:%v \r\n", udpAddr.String())
	/*
		|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		| 1  |  1  | X'00' |  1   | Variable |    2     |
	*/
	temp := make([]byte, 6)
	_, err := io.ReadFull(clientConn, temp)
	if err != nil {
		return err
	}
	bindPort := udpAddr.Port
	//版本 | 代理的应答 |　保留1字节　| 地址类型 | 代理服务器地址 | 绑定的代理端口
	bindMsg := []byte{0x05, 0x00, 0x00, 0x01}
	buffer := bytes.NewBuffer(bindMsg)
	binary.Write(buffer, binary.BigEndian, udpAddr.IP.To4())
	binary.Write(buffer, binary.BigEndian, uint16(bindPort))
	clientConn.Write(buffer.Bytes())
	return nil
}

/*
to socks5
cmd socks cmd
addrtype socks type  0x01  0x03  0x04
read Back
*/
func SocksCmd(socksConn net.Conn, cmd uint8, addrType uint8, host string, readBack bool) error {
	//socks5 auth
	socksConn.Write([]byte{0x05, 0x01, 0x00})
	//connect head
	hosts := strings.Split(host, ":")
	_port, _ := strconv.Atoi(hosts[1])
	msg := []byte{0x05, cmd, 0x00, addrType}
	buffer := bytes.NewBuffer(msg)
	switch addrType {
	case 0x01:
		rAddr := net.ParseIP(hosts[0])
		//ip
		binary.Write(buffer, binary.BigEndian, rAddr.To4())
		break
	case 0x03:
		buffer.WriteByte(uint8(len(hosts[0])))
		buffer.Write([]byte(hosts[0]))
		break
	case 0x04:
		rAddr := net.ParseIP(hosts[0])
		binary.Write(buffer, binary.BigEndian, rAddr.To16())
		break

	}

	//port
	binary.Write(buffer, binary.BigEndian, uint16(_port))
	socksConn.Write(buffer.Bytes())

	//recv auth back
	authBack := make([]byte, 2)
	_, err := io.ReadFull(socksConn, authBack)
	if err != nil {
		log.Println("SocksCmd err:" + err.Error())
		return err
	}
	if authBack[0] != 0x05 || authBack[1] != 0x00 {
		log.Println("auth error")
		return errors.New("auth error")
	}

	if readBack {
		//recv connectBack
		connectBack := make([]byte, 10)
		_, err = io.ReadFull(socksConn, connectBack)
		if err != nil {
			log.Println("SocksCmd err1:" + err.Error())
			return err
		}
	}
	return nil
}
