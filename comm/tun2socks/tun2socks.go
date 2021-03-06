package tun2socks

import (
	"bytes"
	"context"
	"goSocksTap/comm/netstack"
	"io"
	"log"

	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func ForwardTransportFromIo(dev io.ReadWriteCloser, mtu int, tcpCallback netstack.ForwarderCall, udpCallback netstack.UdpForwarderCall) error {
	_, channelLinkID, err := netstack.NewDefaultStack(mtu, tcpCallback, udpCallback)
	if err != nil {
		log.Printf("err:%v", err)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// write tun
	go func(_ctx context.Context) {
		var sendBuffer = new(bytes.Buffer)
		for {
			info := channelLinkID.ReadContext(_ctx)
			if info == nil {
				log.Printf("channelLinkID exit \r\n")
				break
			}
			sendBuffer.Reset()
			//buffer.Write(pkt.Pkt.LinkHeader().View())
			sendBuffer.Write(info.NetworkHeader().View())
			sendBuffer.Write(info.TransportHeader().View())
			sendBuffer.Write(info.Data().AsRange().ToOwnedView())
			if sendBuffer.Len() > 0 {
				dev.Write(sendBuffer.Bytes())
			}
		}
	}(ctx)

	// read tun data
	var buf = make([]byte, mtu+80)
	for {
		n, e := dev.Read(buf[:])
		if e != nil {
			log.Printf("err:%v", err)
			break
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Data: buffer.NewViewFromBytes(buf[:n]).ToVectorisedView(),
		})
		switch header.IPVersion(buf[:]) {
		case header.IPv4Version:
			channelLinkID.InjectInbound(header.IPv4ProtocolNumber, pkt)
		case header.IPv6Version:
			channelLinkID.InjectInbound(header.IPv6ProtocolNumber, pkt)
		}
		pkt.DecRef()
	}
	return nil
}
