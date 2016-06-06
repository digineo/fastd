package fastd

import (
	"errors"
	"net"
)

// not implemented

func CloneIface(name string) string {
	return ""
}

func DestroyIface(name string) {
}

func SetRemote(ifname string, remote *Sockaddr, pubkey []byte) error {
	return errors.New("not implemented")
}

func GetRemote(ifname string) (remote *Sockaddr, pubkey []byte, err error) {
	return nil, nil, errors.New("not implemented")
}

func SetAddr(ifname string, addr, dstaddr net.IP) (err error) {
	return nil
}

func GetStats(ifname string) (*IfaceStats, error) {
	return nil, errors.New("not implemented")
}
