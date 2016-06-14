package ifconfig

import (
	"C"
	"errors"
	"syscall"
	"unsafe"
)

// not implemented

func GetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	return errors.New("not implemented")
}

func SetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	return errors.New("not implemented")
}

func Clone(name string, data unsafe.Pointer) (string, error) {
	return "", errors.New("not implemented")
}

func Destroy(name string) {
	// TODO
}

func SetAddrPTP(ifname string, addr, dstaddr *syscall.RawSockaddrAny) (err error) {
	return errors.New("not implemented")
}

func SetAddr(ifname string, addr *syscall.RawSockaddrAny, prefixlen uint8) (err error) {
	return errors.New("not implemented")
}
