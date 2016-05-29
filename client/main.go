package main

import (
	"flag"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

var (
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

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "server":
		var listenAddr, implName, secret string
		var listenPort uint

		// Parse flags
		flags := flag.NewFlagSet("fastd", flag.ExitOnError)
		flags.StringVar(&implName, "impl", "udp", "Implementation type: udp or kernel")
		flags.StringVar(&listenAddr, "address", "0.0.0.0", "Listening address")
		flags.StringVar(&secret, "secret", "", "Secret key")
		flags.UintVar(&listenPort, "port", 10000, "Listening port")
		flags.Parse(args)

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
	case "remote":
		port, _ := strconv.Atoi(args[2])
		SetRemote(args[0], &Sockaddr{IP: net.ParseIP(args[1]), Port: uint16(port)})
	case "inet":
		SetAlias(args[0],
			&Sockaddr{IP: net.ParseIP(args[1])},
			&Sockaddr{IP: net.ParseIP(args[2])},
		)
	default:
		println("invalid command:", cmd)
		os.Exit(1)
	}
}
