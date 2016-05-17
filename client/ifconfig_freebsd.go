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

type ifconfigParam struct {
	remote [18]byte
}

// Set remote address
func ifconfig(args []string) {
	ifname := args[0]
	ipaddr := args[1]
	port, _ := strconv.Atoi(args[2])

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		panic(err)
	}
	defer syscall.Close(fd)

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

	recode := ioctl(uintptr(fd), ioctl_SET_DRV_SPEC, uintptr(unsafe.Pointer(ifd)))
	log.Println(recode)
}
