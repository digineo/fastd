package main

import (
	"syscall"
	"unsafe"
)

func (addr *Sockaddr) WriteNative(sockaddr *syscall.RawSockaddr) {
	switch addr.Family() {
	case syscall.AF_INET:
		raw := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sockaddr))
		raw.Len = syscall.SizeofSockaddrInet4
		raw.Family = syscall.AF_INET
		raw.Port = uint16toh(addr.Port)
		copy(raw.Addr[:], addr.IP.To4())
	case syscall.AF_INET6:
		raw := (*syscall.RawSockaddrInet6)(unsafe.Pointer(sockaddr))
		raw.Len = syscall.SizeofSockaddrInet6
		raw.Family = syscall.AF_INET6
		raw.Port = uint16toh(addr.Port)
		copy(raw.Addr[:], addr.IP.To16())
	default:
		panic("unknown family")
	}
}
