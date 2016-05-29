package main

/*
#include <net/if.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
*/
import "C"

import (
	"bytes"
	"log"
	"net"
	"syscall"
	"unsafe"
)

const (
	FASTD_PARAM_GET = iota
	FASTD_PARAM_WITH_REMOTE
)

var (
	// File descriptor for ioctl on fastd network interfaces
	controlFd = newControlFd()

	tunnelMaskIPv4 = net.IPv4(255, 255, 255, 255)
	tunnelMaskIPv6 = net.IP(bytes.Repeat([]byte{255}, 16))
)

type ifconfigParam struct {
	remote [18]byte
}

func newControlFd() int {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}
	return fd
}

// Set remote address
func SetRemote(ifname string, remote *Sockaddr) {

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

	recode := ioctl(uintptr(controlFd), ioctl_SET_DRV_SPEC, uintptr(unsafe.Pointer(ifd)))
	log.Println(recode)
}

func CloneIface(name string) string {
	log.Println("SIOCIFCREATE", name)
	return ioctl_ifreq(ioctl_SIOCIFCREATE, name)
}

func DestroyIface(name string) string {
	return ioctl_ifreq(ioctl_SIOCIFDESTROY, name)
}

func SetAlias(ifname string, src, dst *Sockaddr) error {
	// Delete alias
	ioctl_ifreq(ioctl_SIOCDIFADDR, ifname)
	var mask *net.IP

	if isIPv4(src.IP) {
		mask = &tunnelMaskIPv4
	} else {
		mask = &tunnelMaskIPv6
	}
	return AddAlias(ifname, src, dst, &Sockaddr{IP: *mask})
}

func AddAlias(ifname string, src, dst, mask *Sockaddr) error {
	req := C.struct_in_aliasreq{}
	// source address
	src.WriteNative((*syscall.RawSockaddr)(unsafe.Pointer(&req.ifra_addr)))
	// destination address
	dst.WriteNative((*syscall.RawSockaddr)(unsafe.Pointer(&req.ifra_broadaddr)))
	// mask
	mask.WriteNative((*syscall.RawSockaddr)(unsafe.Pointer(&req.ifra_mask)))

	// copy ifname
	for i, c := range ifname {
		req.ifra_name[i] = C.char(c)
	}

	return ioctl(uintptr(controlFd), ioctl_SIOCAIFADDR, uintptr(unsafe.Pointer(&req)))
}

// Executes ioctl with a ifreq{}
func ioctl_ifreq(ioctlId uintptr, ifname string) string {
	req := C.struct_ifreq{}

	// copy ifname
	for i, c := range ifname {
		req.ifr_name[i] = C.char(c)
	}

	recode := ioctl(uintptr(controlFd), ioctlId, uintptr(unsafe.Pointer(&req)))
	if recode != nil {
		return ""
	}

	return C.GoString(&req.ifr_name[0])
}
