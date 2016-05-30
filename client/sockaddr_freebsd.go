package main

/*
#include <netinet/in.h>
*/
import "C"

import (
	"syscall"
	"unsafe"
)

/*
	Returns a struct sockaddr_storage* that is in fact a sockaddr_in* or sockaddr_in6*
*/
func (addr *Sockaddr) Native() *C.struct_sockaddr_storage {
	switch addr.Family() {
	case syscall.AF_INET:
		raw := syscall.RawSockaddrInet4{
			Len:    syscall.SizeofSockaddrInet4,
			Family: syscall.AF_INET,
			Port:   uint16toh(addr.Port),
		}
		copy(raw.Addr[:], addr.IP.To4())
		return (*C.struct_sockaddr_storage)(unsafe.Pointer(&raw))
	case syscall.AF_INET6:
		raw := syscall.RawSockaddrInet6{
			Len:      syscall.SizeofSockaddrInet6,
			Family:   syscall.AF_INET6,
			Port:     uint16toh(addr.Port),
			Scope_id: addr.ScopeId,
		}
		copy(raw.Addr[:], addr.IP.To16())
		return (*C.struct_sockaddr_storage)(unsafe.Pointer(&raw))
	default:
		panic("unknown family")
	}
}
