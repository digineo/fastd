package main

/*
#include <netinet/in.h>
*/
import "C"

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

var (
	listenPort uint16 = 8000
	listenAddr        = net.ParseIP("127.0.0.1")
)

var (
	ioctl_BIND  = _IOW('F', 1, unsafe.Sizeof(syscall.RawSockaddr{}))
	ioctl_CLOSE = _IO('F', 2)
)

func main() {
	// close previous socket
	close()

	// create new socket
	if err := bind(); err != nil {
		panic(err)
	}
}

func bind() error {
	f, err := os.OpenFile("/dev/fastd", os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	addr := sockaddr(listenAddr, listenPort)

	return ioctl(f.Fd(), ioctl_BIND, uintptr(addr))
}

func close() error {
	f, err := os.OpenFile("/dev/fastd", os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return ioctl(f.Fd(), ioctl_CLOSE, 0)
}
