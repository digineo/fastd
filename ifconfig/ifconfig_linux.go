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

func Clone(name string) string {
	return "fastd0"
}

func Destroy(name string) {
	// TODO
}

func SetAddr(ifname string, addr, dstaddr *syscall.RawSockaddrAny) (err error) {
	return errors.New("not implemented")
}
