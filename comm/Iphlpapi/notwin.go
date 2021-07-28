// +build !windows


package Iphlpapi


func PortGetPid(lSocks string) (int,error) {
	return 0,nil;
}

func GetUdpAddrByPid(pid int)error{
	return nil;
}

func IsSocksServerAddr(pid int,addr string)bool{
	return true;
}