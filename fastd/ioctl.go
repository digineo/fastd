package fastd

import (
	"log"
	"syscall"
)

// nolint: golint
var (
	ioctl_LIST  = _IO('F', 1)
	ioctl_BIND  = _IOW('F', 2, 18)
	ioctl_CLOSE = _IOW('F', 3, 18)
)

// Ioctl executes a IOCTL syscall
func Ioctl(fd, cmd, ptr uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, ptr)
	if e != 0 {
		log.Printf("errno=%d %s", int(e), e)
		return e
	}
	return nil
}
