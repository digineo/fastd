package ifconfig

import (
	"net"
)

func IsIPv4(ip net.IP) bool {
	return len(ip) == net.IPv4len || (len(ip) > 11 && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff)
}

func isZeros(ip net.IP) bool {
	for _, b := range ip {
		if b != 0 {
			return false
		}
	}
	return true
}
