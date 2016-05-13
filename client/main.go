package main

/*
#include <netinet/in.h>
*/
import "C"

import (
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

var (
	listenPort uint16 = 8000
	listenAddr        = net.ParseIP("0.0.0.0")
)

var (
	ioctl_BIND  = _IOW('F', 1, unsafe.Sizeof(syscall.RawSockaddr{}))
	ioctl_CLOSE = _IO('F', 2)
)

func main() {
	log.Println(close())
	log.Println(bindSocket())
}

func bindSocket() error {
	f, err := os.OpenFile("/dev/fastd", os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	addr := &syscall.RawSockaddrInet4{
		Len:    syscall.SizeofSockaddrInet4,
		Family: syscall.AF_INET,
		Port:   listenPort,
	}
	copy(addr.Addr[:], listenAddr.To4())

	return ioctl(f.Fd(), ioctl_BIND, uintptr(unsafe.Pointer(addr)))
}

func close() error {
	f, err := os.OpenFile("/dev/fastd", os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return ioctl(f.Fd(), ioctl_CLOSE, 0)
}
