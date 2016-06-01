package main

/*
#include <stdlib.h>
#include "ifconfig.h"
*/
import "C"

import (
	"log"
	"syscall"
	"unsafe"
)

const (
	FASTD_PARAM_GET = iota
	FASTD_PARAM_WITH_REMOTE
)

var (
	// File descriptor for ioctl on fastd network interfaces
	controlFd4 = newControlFd(syscall.AF_INET)
	controlFd6 = newControlFd(syscall.AF_INET6)
)

type ifconfigParam struct {
	remote [18]byte
}

func newControlFd(af int) int {
	fd, err := syscall.Socket(af, syscall.SOCK_DGRAM, 0)
	if err != nil {
		panic(err)
	}

	if res := C.set_fd(C.sa_family_t(af), C.int(fd)); res != 0 {
		panic("set_fd() failed")
	}
	return fd
}

// Set remote address
func SetRemote(ifname string, remote *Sockaddr) error {

	param := &ifconfigParam{
		remote: remote.RawFixed(),
	}

	ifd := &C.struct_ifdrv{
		ifd_cmd:  FASTD_PARAM_WITH_REMOTE,
		ifd_data: unsafe.Pointer(param),
		ifd_len:  C.size_t(unsafe.Sizeof(*param)),
	}

	// copy ifname
	for i, c := range ifname {
		ifd.ifd_name[i] = C.char(c)
	}

	return ioctl(uintptr(controlFd4), ioctl_SET_DRV_SPEC, uintptr(unsafe.Pointer(ifd)))
}

func CloneIface(name string) string {
	log.Println("SIOCIFCREATE", name)
	return ioctl_ifreq(ioctl_SIOCIFCREATE, name)
}

func DestroyIface(name string) string {
	return ioctl_ifreq(ioctl_SIOCIFDESTROY, name)
}

func SetAlias(ifname string, addr, dstaddr *Sockaddr) (err error) {
	var res uintptr
	name := C.CString(ifname)
	defer C.free(unsafe.Pointer(name))

	if isIPv4(addr.IP) {
		res = uintptr(C.remove_alias4(name))
		if res != 0 {
			log.Println("alias4_remove:", syscall.Errno(res))
		}

		res = uintptr(C.add_alias4(name, addr.Native(), dstaddr.Native()))

	} else {
		res = uintptr(C.remove_alias6(name, addr.Native()))
		if res != 0 {
			log.Println("alias6_remove:", syscall.Errno(res))
		}

		res = uintptr(C.add_alias6(name, addr.Native(), dstaddr.Native()))
	}

	if res != 0 {
		err = syscall.Errno(res)
	}
	return
}

// Executes ioctl with a ifreq{}
func ioctl_ifreq(ioctlId uintptr, ifname string) string {
	req := C.struct_ifreq{}

	// copy ifname
	for i, c := range ifname {
		req.ifr_name[i] = C.char(c)
	}

	recode := ioctl(uintptr(controlFd4), ioctlId, uintptr(unsafe.Pointer(&req)))
	if recode != nil {
		return ""
	}

	return C.GoString(&req.ifr_name[0])
}
