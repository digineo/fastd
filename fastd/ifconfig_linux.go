package fastd

import (
	"net"
)

// not implemented

func CloneIface(name string) string {
	return ""
}

func DestroyIface(name string) string {
	return ""
}

func SetRemote(ifname string, remote *Sockaddr) {
}

func SetAddr(ifname string, addr, dstaddr net.IP) (err error) {
	return nil
}
