//go:build wasm
// +build wasm

package netstat

/**/
func PortGetPid(lSocks string) (int, error) {
	return 0, nil
}
func IsSocksServerAddr(pid int, addr string) bool {
	return false
}

func GetTcpBindList(pid int, slefPid bool) ([]uint16, error) {
	var ports []uint16
	return ports, nil
}
