package ifconfig

import (
	"net"
	"syscall"
	"unsafe"
)

/*
	Returns a struct sockaddr_storage* that is in fact a sockaddr_in* or sockaddr_in6*
*/
func Sockaddr(addr net.IP) *syscall.RawSockaddrAny {
	if bytes := addr.To4(); bytes != nil {
		raw := syscall.RawSockaddrInet4{
			Len:    syscall.SizeofSockaddrInet4,
			Family: syscall.AF_INET,
		}
		copy(raw.Addr[:], bytes)
		return (*syscall.RawSockaddrAny)(unsafe.Pointer(&raw))
	} else if bytes := addr.To16(); bytes != nil {
		raw := syscall.RawSockaddrInet6{
			Len:    syscall.SizeofSockaddrInet6,
			Family: syscall.AF_INET6,
		}
		copy(raw.Addr[:], bytes)
		return (*syscall.RawSockaddrAny)(unsafe.Pointer(&raw))
	} else {
		return nil
	}
}
