package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func main() {
	eth0, err := netlink.LinkByName("eth0") // 替换为实际接口名
	if err != nil {
		log.Fatalf("获取 eth0 失败: %v", err)
	}
	// 1. 加载 eBPF 程序
	spec, _ := ebpf.LoadCollectionSpec("bpf_bpfel.o")
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("加载ebpf失败: %v", err)
	}
	defer coll.Close()
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: eth0.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		fmt.Printf("could not get replace qdisc: %w", err)
		return
	}

	prog := coll.Programs["egress_prog_func"]
	fmt.Printf("fd:%d\r\n", prog.FD())

	filter1 := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: eth0.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			//Handle:    1,
			Handle:   netlink.MakeHandle(0x2023, 0b100+uint16(1)),
			Protocol: unix.ETH_P_ALL,
			Priority: 1,
		},
		Fd:           prog.FD(),
		Name:         prog.String(),
		DirectAction: true,
	}

	fmt.Printf("eth0.Attrs().Index:%+v %+v\r\n", filter1, eth0.Attrs().Index)
	// 3. 附加到 TC
	if err := netlink.FilterReplace(filter1); err != nil {
		panic(err)
	}
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the counters maps.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if coll.Variables["egress_pkt_count"] != nil {
			var egress_pkt_count uint64
			if err := coll.Variables["egress_pkt_count"].Get(&egress_pkt_count); err != nil {
				fmt.Printf("ddd err\r\n")
			}
			var ingress_pkt_count uint64
			if err := coll.Variables["ingress_pkt_count"].Get(&ingress_pkt_count); err != nil {
				fmt.Printf("ddd err\r\n")
			}
			log.Printf("Packet Count: %d %d\n", egress_pkt_count, ingress_pkt_count)
		}
	}

	fmt.Print("请输入回车继续...")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if scanner.Text() == "" {
			break
		}
	}
}
