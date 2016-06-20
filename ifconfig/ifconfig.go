package ifconfig

import (
	"net"
)

func IsIPv4(ip net.IP) bool {
	return ip.To4() != nil
}
