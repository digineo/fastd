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
	"net"
	"syscall"
	"unsafe"
)

// Initializes AF_INET and AF_INET6 control sockets that are required by many of the C functions
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

	return retval(C.get_drv_spec(name, cmd, data, C.size_t(len)))
}

func SetDrvSpec(ifname string, cmd C.ulong, data unsafe.Pointer, len uintptr) error {
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	return retval(C.set_drv_spec(name, cmd, data, C.size_t(len)))
}

func Clone(name string, data unsafe.Pointer) (string, error) {
	var ifname [C.IFNAMSIZ]C.char

	for i, c := range name {
		ifname[i] = C.char(c)
	}

	err := C.if_clone(&ifname[0], data)

	if err != 0 {
		return "", syscall.Errno(err)
	} else {
		return C.GoString(&ifname[0]), nil
	}
}

func GetMTU(ifname string) (uint16, error) {
	c_ifname := C.CString(ifname)
	defer C.free(unsafe.Pointer(c_ifname))

	var mtu C.int
	if err := C.get_mtu(c_ifname, &mtu); err != 0 {
		return 0, syscall.Errno(err)
	} else {
		return uint16(mtu), nil
	}
}

func SetMTU(ifname string, mtu uint16) error {
	c_ifname := C.CString(ifname)
	defer C.free(unsafe.Pointer(c_ifname))

	return retval(C.set_mtu(c_ifname, C.int(mtu)))
}

func GetDescr(ifname string) (string, error) {
	var c_descr [64]C.char
	c_ifname := C.CString(ifname)
	defer C.free(unsafe.Pointer(c_ifname))

	if err := C.get_descr(c_ifname, &c_descr[0], C.size_t(len(c_descr))); err != 0 {
		return "", syscall.Errno(err)
	} else {
		return C.GoString(&c_descr[0]), nil
	}
}

func SetDescr(ifname string, descr string) error {
	c_ifname := C.CString(ifname)
	c_descr := C.CString(descr)
	defer C.free(unsafe.Pointer(c_ifname))
	defer C.free(unsafe.Pointer(c_descr))

	return retval(C.set_descr(c_ifname, c_descr))
}

func Destroy(name string) error {
	var ifname [C.IFNAMSIZ]C.char

	for i, c := range name {
		ifname[i] = C.char(c)
	}

	return retval(C.if_destroy(&ifname[0]))
}

func SetAddr(ifname string, addr net.IP, prefixlen uint8) (err error) {
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	if IsIPv4(addr) {
		return syscall.EAFNOSUPPORT
	}

	addr_sa := (*C.struct_sockaddr_in6)(unsafe.Pointer(Sockaddr(addr)))
	return retval(C.add_addr6(name, addr_sa, C.uint8_t(prefixlen)))
}

func SetAddrPTP(ifname string, addr, dstaddr net.IP) (err error) {
	var res C.int
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	if IsIPv4(addr) {
		C.remove_addr4(name)
		addr_sa := (*C.struct_sockaddr_in)(unsafe.Pointer(Sockaddr(addr)))
		dstaddr_sa := (*C.struct_sockaddr_in)(unsafe.Pointer(Sockaddr(dstaddr)))
		res = C.add_addr4_ptp(name, addr_sa, dstaddr_sa)
	} else {
		addr_sa := (*C.struct_sockaddr_in6)(unsafe.Pointer(Sockaddr(addr)))
		dstaddr_sa := (*C.struct_sockaddr_in6)(unsafe.Pointer(Sockaddr(dstaddr)))
		C.remove_addr6(name, addr_sa)
		res = C.add_addr6_ptp(name, addr_sa, dstaddr_sa)
	}

	return retval(res)
}
