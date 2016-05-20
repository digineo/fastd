package main

/*
#include <netinet/in.h>
#include <net/if.h>
*/
import "C"

import (
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

var (
	listenPort uint16 = 8000
	listenAddr        = net.ParseIP("127.0.0.1")
)

var (
	ioctl_BIND         = _IOW('F', 1, unsafe.Sizeof(syscall.RawSockaddr{}))
	ioctl_CLOSE        = _IO('F', 2)
	ioctl_SET_DRV_SPEC = _IOW('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))
	ioctl_GET_DRV_SPEC = _IOWR('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))
)

func main() {
	if len(os.Args) < 2 {
		println("no arguments given")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		var srv Server
		srv, err := NewKernelServer(listenAddr, listenPort)
		if err != nil {
			panic(err)
		}

		// Handle incoming packets
		go func() {
			for msg := range srv.Read() {
				if reply := handlePacket(msg); reply != nil {
					println("sending reply")
					srv.Write(reply)
				}
			}
		}()

		// Wait for SIGINT or SIGTERM
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs

		srv.Close()
	case "ifconfig":
		ifconfig(os.Args[2:])
	}
}
