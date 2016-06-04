package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/corny/fastd/fastd"
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

		config := fastd.Config{
			Bind: []fastd.Sockaddr{{net.ParseIP(listenAddr), uint16(listenPort), 0}},
		}
		config.SetServerKey(secret)

		srv, err := fastd.NewServer(implName, &config)
		if err != nil {
			println("unable to start server:", err)
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
		err := fastd.SetAddr(args[0], net.ParseIP(args[1]), net.ParseIP(args[2]))
		if err != nil {
			println(err.Error())
			os.Exit(1)
		}
	case "ifstat":
		if stats, err := fastd.GetStats(args[0]); err != nil {
			println(err.Error())
			os.Exit(1)
		} else {
			fmt.Printf("%+v", stats)
		}

	default:
		println("invalid command:", cmd)
		os.Exit(1)
	}
}
