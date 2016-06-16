package ifconfig

import (
	"C"
	"errors"
	"net"
	"unsafe"
)

var notImplemented = errors.New("not implemented")

func GetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	return notImplemented
}

func SetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	return notImplemented
}

func Clone(name string, data unsafe.Pointer) (string, error) {
	return "fastd", nil
}

func Destroy(name string) {
	// TODO
}

func GetMTU(ifname string) (int, error) {
	return 0, notImplemented
}

func SetMTU(ifname string, mtu int) error {
	return notImplemented
}

func GetDescr(ifname string) (string, error) {
	return "", notImplemented
}

func SetDescr(ifname string, descr string) error {
	return notImplemented
}

func SetAddrPTP(ifname string, addr, dstaddr net.IP) (err error) {
	return notImplemented
}

func SetAddr(ifname string, addr net.IP, prefixlen uint8) (err error) {
	return notImplemented
}
