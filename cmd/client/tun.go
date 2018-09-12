package main

import (
	"io"
	"net"
)

// Interface is an abstraction for Linux and FreeBSD TUN devices.
type Interface interface {
	io.Reader
	io.Writer

	// Name returns the interface name.
	Name() string

	// Configure adds local IP addresses and sets the MTU.
	Configure(uint16, ...*net.IPNet) error

	// Close destroys the interface.
	Close() error
}
