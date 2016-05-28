package main

/*
#include <net/if.h>
*/
import "C"

import (
	"log"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	FASTD_PARAM_GET = iota
	FASTD_PARAM_WITH_REMOTE
)

var (
	controlFd = newControlFd()
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
func ifconfig(args []string) {
	log.Println("created:", CloneIface("fastd"))
	return

	ifname := args[0]
	ipaddr := args[1]
	port, _ := strconv.Atoi(args[2])

	sockaddr := Sockaddr{
		IP:   net.ParseIP(ipaddr).To16(),
		Port: uint16(port),
	}

	param := &ifconfigParam{
		remote: sockaddr.RawFixed(),
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
	return cloneDestroyInterface(ioctl_SIOCIFCREATE, name)
}

func DestroyIface(name string) string {
	return cloneDestroyInterface(ioctl_SIOCIFDESTROY, name)
}

func cloneDestroyInterface(ioctlId uintptr, name string) string {
	req := &C.struct_ifreq{}
	for i, c := range name {
		req.ifr_name[i] = C.char(c)
	}

	recode := ioctl(uintptr(controlFd), ioctlId, uintptr(unsafe.Pointer(req)))
	if recode != nil {
		return ""
	}

	return C.GoString(&req.ifr_name[0])
}
