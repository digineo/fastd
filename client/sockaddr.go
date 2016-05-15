package main

import (
	"net"
	"syscall"
)

func uint16toh(i uint16) uint16 {
	return (i << 8) | (i >> 8)
}

func parseRawSockaddr(buf []byte) (ip net.IP, port uint16) {
	if len(buf) < 8 {
		return
	}

	port = (uint16(buf[2]) << 8) | uint16(buf[3])

	switch buf[1] {
	case syscall.AF_INET:
		ip = net.IP(buf[4:8])
	case syscall.AF_INET6:
		if len(buf) >= 20 {
			ip = net.IP(buf[4:20])
		}
	}
	return
}
