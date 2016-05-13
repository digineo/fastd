package main

import (
	"net"
	"syscall"
	"unsafe"
)

func uint16toh(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}

func sockaddr(ip net.IP, port uint16) unsafe.Pointer {

	addr := &syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
		Port:   uint16toh(port),
	}
	copy(addr.Addr[:], ip.To4())
	return unsafe.Pointer(addr)
}
