package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/digineo/fastd/fastd"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("no arguments given")
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
		flags.StringVar(&listenAddr, "address", "127.0.0.1", "Listening address")
		flags.StringVar(&secret, "secret", "", "Secret key")
		flags.UintVar(&listenPort, "port", 10000, "Listening port")
		flags.Parse(args)

		// Initialize secret key
		if secret == "" {
			fmt.Println("secret key missing")
			flags.PrintDefaults()
			os.Exit(1)
		}

		config := fastd.Config{
			Bind: []fastd.Sockaddr{{net.ParseIP(listenAddr), uint16(listenPort)}},
			AssignAddresses: func(peer *fastd.Peer) {
				// Generate addresses for test purposes
				index, _ := strconv.Atoi(peer.Ifname[5:])
				if index > 128 {
					panic("interface index out of range")
				}
				peer.IPv4.LocalAddr = net.IPv4(192, 168, 23, byte(index)*2)
				peer.IPv4.DestAddr = net.IPv4(192, 168, 23, byte(index)*2+1)
			},
		}

		err := config.SetServerKey(secret)
		if err != nil {
			panic(err)
		}

		srv, err := fastd.NewServer(implName, &config)
		if err != nil {
			fmt.Println("unable to start server:", err)
			os.Exit(1)
		}

		// Wait for SIGINT or SIGTERM
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		<-sigs

		srv.Stop()
	case "remote":
		port, _ := strconv.Atoi(args[2])
		fastd.SetRemote(args[0], &fastd.Sockaddr{IP: net.ParseIP(args[1]), Port: uint16(port)}, nil)
	case "addr":
		err := fastd.SetAddrPTP(args[0], net.ParseIP(args[1]), net.ParseIP(args[2]))
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
	case "ifstat":
		if stats, err := fastd.GetStats(args[0]); err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		} else {
			fmt.Printf("%+v", stats)
		}

	default:
		fmt.Println("invalid command:", cmd)
		os.Exit(1)
	}
}
