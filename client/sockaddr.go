package main

import (
	"net"
	"syscall"
)

func uint16toh(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}

func parseRawSockaddr(buf []byte) *Sockaddr {
	if len(buf) < 8 {
		// too short for IPv4
		return nil
	}

	addr := &Sockaddr{
		Port: (uint16(buf[2]) << 8) | uint16(buf[3]),
	}

	switch buf[1] {
	case syscall.AF_INET:
		// IPv4
		addr.IP = net.IP(buf[4:8])
	case syscall.AF_INET6:
		// IPv6
		if len(buf) < 20 {
			return nil
		}
		addr.IP = net.IP(buf[4:20])
	default:
		return nil
	}

	return addr
}
