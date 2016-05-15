package main

import (
	"net"
	"syscall"
	"unsafe"
)

func sockaddrToRaw(ip net.IP, port uint16) unsafe.Pointer {
	addr := &syscall.RawSockaddrInet4{
		Family: syscall.AF_INET,
		Port:   uint16toh(port),
	}
	copy(addr.Addr[:], ip.To4())
	return unsafe.Pointer(addr)
}
