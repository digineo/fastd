package ifconfig

import (
	"C"
	"net"
	"syscall"
)

func IsIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// Converts the given value to a syscall.Errno if it is not zero
func retval(val C.int) error {
	if val == 0 {
		return nil
	} else {
		return syscall.Errno(val)
	}
}
