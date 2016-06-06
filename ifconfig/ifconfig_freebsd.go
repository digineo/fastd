package ifconfig

/*
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ifconfig.h"
*/
import "C"

import (
	"fmt"
	"syscall"
	"unsafe"
)

func init() {
	if res := C.set_fd(syscall.AF_INET); res != 0 {
		panic(fmt.Sprintln("set_fd(AF_INET) failed:", syscall.Errno(res)))
	}
	if res := C.set_fd(syscall.AF_INET6); res != 0 {
		panic(fmt.Sprintln("set_fd(AF_INET6) failed:", syscall.Errno(res)))
	}
}

func GetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	if res := C.get_drv_spec(name, cmd, data, C.size_t(len)); res == 0 {
		return nil
	} else {
		return syscall.Errno(res)
	}
}

func SetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	if res := C.set_drv_spec(name, cmd, data, C.size_t(len)); res == 0 {
		return nil
	} else {
		return syscall.Errno(res)
	}
}

func Clone(name string) string {
	var ifname [C.IFNAMSIZ]C.char

	for i, c := range name {
		ifname[i] = C.char(c)
	}

	err := C.if_clone(&ifname[0])

	if err != 0 {
		return ""
	} else {
		return C.GoString(&ifname[0])
	}
}

func Destroy(name string) error {
	var ifname [C.IFNAMSIZ]C.char

	for i, c := range name {
		ifname[i] = C.char(c)
	}

	if err := C.if_destroy(&ifname[0]); err != 0 {
		return syscall.Errno(err)
	} else {
		return nil
	}
}

func SetAddr(ifname string, addr, dstaddr *syscall.RawSockaddrAny) (err error) {
	var res uintptr
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	switch addr.Addr.Family {
	case syscall.AF_INET:
		C.remove_addr4(name)
		addr_sa := (*C.struct_sockaddr_in)(unsafe.Pointer(addr))
		dstaddr_sa := (*C.struct_sockaddr_in)(unsafe.Pointer(dstaddr))
		res = uintptr(C.add_addr4(name, addr_sa, dstaddr_sa))
	case syscall.AF_INET6:
		addr_sa := (*C.struct_sockaddr_in6)(unsafe.Pointer(addr))
		dstaddr_sa := (*C.struct_sockaddr_in6)(unsafe.Pointer(dstaddr))
		C.remove_addr6(name, addr_sa)
		res = uintptr(C.add_addr6(name, addr_sa, dstaddr_sa))
	default:
		return syscall.EAFNOSUPPORT
	}

	if res != 0 {
		err = syscall.Errno(res)
	}

	return
}
