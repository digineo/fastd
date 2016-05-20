package main

/*
#include <netinet/in.h>
#include <net/if.h>
*/
import "C"

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"unsafe"
)

var (
	ioctl_BIND         = _IOW('F', 1, unsafe.Sizeof(syscall.RawSockaddr{}))
	ioctl_CLOSE        = _IO('F', 2)
	ioctl_SET_DRV_SPEC = _IOW('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))
	ioctl_GET_DRV_SPEC = _IOWR('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))

	implementations = map[string]ServerFactory{
		"udp":    NewUDPServer,
		"kernel": NewKernelServer,
	}
)

func main() {
	if len(os.Args) < 2 {
		println("no arguments given")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		var listenAddr, implName, secret string
		var listenPort uint

		// Parse flags
		flags := flag.NewFlagSet("fastd", flag.ExitOnError)
		flags.StringVar(&implName, "impl", "udp", "Implementation type: udp or kernel")
		flags.StringVar(&listenAddr, "address", "0.0.0.0", "Listening address")
		flags.StringVar(&secret, "secret", "", "Secret key")
		flags.UintVar(&listenPort, "port", 10000, "Listening port")
		flags.Parse(os.Args[2:])

		if secret == "" {
			println("secret key missing\n")
			flags.PrintDefaults()
			os.Exit(1)
		}
		config.SetServerKey(secret)

		// Get implementation
		impl := implementations[implName]
		if impl == nil {
			println("unknown implementation:", impl)
			os.Exit(1)
		}

		// Initialize implementation
		srv, err := impl(net.ParseIP(listenAddr), uint16(listenPort))
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
