package fastd

import (
	"errors"
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

func GetStats(ifname string) (*IfaceStats, error) {
	return nil, errors.New("not implemented")
}
