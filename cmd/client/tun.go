package main

import "net"

// Interface is an abstraction for Linux and FreeBSD TUN devices.
type Interface interface {
	// Name returns the interface name.
	Name() string

	// SetupEndpoints configures the tunnel with local and remote IP
	// address and MTU.
	Configure(net.IP, net.IP, uint16) error

	// Close destroys the interface.
	Close() error
}
