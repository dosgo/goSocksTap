//go:build windows
// +build windows

package comm

//https://github.com/twskipper/route-table
import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"
)

func GetLocalIp() (string, error) {
	addrs, err := net.InterfaceAddrs()

	if err != nil {
		return "", err
	}

	for _, address := range addrs {

		// 检查ip地址判断是否回环地址
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}

		}
	}
	return "", errors.New("can not GetLocalIp")
}

// 注意网络字节序
func Inet_ntoa(ipnr uint32, isBig bool) string {
	ip := net.IPv4(0, 0, 0, 0)
	var bo binary.ByteOrder
	if isBig {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}
	bo.PutUint32([]byte(ip.To4()), ipnr)
	return ip.String()
}

// 注意网络字节序
func Inet_aton(ip string, isBig bool) uint32 {
	var bo binary.ByteOrder
	if isBig {
		bo = binary.BigEndian
	} else {
		bo = binary.LittleEndian
	}
	return bo.Uint32(
		[]byte(net.ParseIP(ip).To4()),
	)
}

type RouteRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

type SliceHeader struct {
	Addr uintptr
	Len  int
	Cap  int
}

type DynamicMemory struct {
	// 保存引用,防止被回收
	mem []byte
}

func NewDynamicMemory(bytes uint32) *DynamicMemory {
	return &DynamicMemory{
		mem: make([]byte, bytes, bytes),
	}
}

func (this *DynamicMemory) Len() uint32 {
	return uint32(len(this.mem))
}

func (this *DynamicMemory) Address() uintptr {
	return (*SliceHeader)(unsafe.Pointer(&this.mem)).Addr
}

type RouteTable struct {
	dll                  *syscall.DLL
	getIpForwardTable    *syscall.Proc
	createIpForwardEntry *syscall.Proc
}

func NewRouteTable() (*RouteTable, error) {
	dll, err := syscall.LoadDLL("iphlpapi.dll")
	if err != nil {
		return nil, err
	}

	getIpForwardTable, err := dll.FindProc("GetIpForwardTable")
	if err != nil {
		return nil, err
	}

	createIpForwardEntry, err := dll.FindProc("CreateIpForwardEntry")
	if err != nil {
		return nil, err
	}

	return &RouteTable{
		dll:                  dll,
		getIpForwardTable:    getIpForwardTable,
		createIpForwardEntry: createIpForwardEntry,
	}, nil
}

func (this *RouteTable) Close() error {
	return this.dll.Release()
}

/*
https://msdn.microsoft.com/en-us/library/windows/desktop/aa366852(v=vs.85).aspx

	typedef struct _MIB_IPFORWARDTABLE {
	  DWORD            dwNumEntries;
	  MIB_IPFORWARDROW table[ANY_SIZE];
	} MIB_IPFORWARDTABLE, *PMIB_IPFORWARDTABLE;
*/
func (this *RouteTable) Routes() ([]RouteRow, error) {
	// 加4,是为了越过DWORD
	mem := NewDynamicMemory(
		uint32(
			4 + unsafe.Sizeof(RouteRow{}),
		),
	)
	table_size := uint32(0)
	// 获取路由表数量
	_, r2, err := this.getIpForwardTable.Call(
		mem.Address(),
		uintptr(unsafe.Pointer(&table_size)),
		0,
	)
	// msdn https://msdn.microsoft.com/en-us/library/windows/desktop/aa365953(v=vs.85).aspx
	if r2 != 0 {
		return nil, err
	}

	// 获取全部路由表
	mem = NewDynamicMemory(table_size)
	_, r2, err = this.getIpForwardTable.Call(
		mem.Address(),
		uintptr(unsafe.Pointer(&table_size)),
		0,
	)
	if r2 != 0 {
		return nil, err
	}

	num := *(*uint32)(unsafe.Pointer(mem.Address()))

	rows := []RouteRow{}
	sh_rows := (*SliceHeader)(unsafe.Pointer(&rows))
	sh_rows.Addr = mem.Address() + 4
	sh_rows.Len = int(num)
	sh_rows.Cap = int(num)
	return rows, nil
}

// 添加路由,需要管理员权限,才能添加成功
func (this *RouteTable) AddRoute(rr RouteRow) error {
	// https://msdn.microsoft.com/en-us/library/windows/desktop/aa365860(v=vs.85).aspx
	_, r2, err := this.createIpForwardEntry.Call(uintptr(unsafe.Pointer(&rr)))
	if r2 != 0 {
		return err
	}
	return nil
}
