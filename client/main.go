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
	ioctl_LIST          = _IO('F', 1)
	ioctl_BIND          = _IOW('F', 2, 18)
	ioctl_CLOSE         = _IOW('F', 3, 18)
	ioctl_SIOCIFCREATE  = _IOWR('i', 122, unsafe.Sizeof(C.struct_ifreq{})) // create clone if
	ioctl_SIOCIFCREATE2 = _IOWR('i', 124, unsafe.Sizeof(C.struct_ifreq{})) // create clone if
	ioctl_SIOCIFDESTROY = _IOW('i', 121, unsafe.Sizeof(C.struct_ifreq{}))  // destroy clone if
	ioctl_SET_DRV_SPEC  = _IOW('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))
	ioctl_GET_DRV_SPEC  = _IOWR('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))

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

		// Initialize secret key
		if secret == "" {
			println("secret key missing\n")
			flags.PrintDefaults()
			os.Exit(1)
		}
		config.SetServerKey(secret)

		// Initialize other stuff
		InitPeers()

		// Get implementation
		impl := implementations[implName]
		if impl == nil {
			println("unknown implementation:", impl)
			os.Exit(1)
		}

		// Initialize implementation
		srv, err := impl([]Sockaddr{{net.ParseIP(listenAddr), uint16(listenPort)}})
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
