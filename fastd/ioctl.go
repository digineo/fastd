package fastd

import (
	"syscall"

	"github.com/sirupsen/logrus"
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
		log.WithFields(logrus.Fields{
			logrus.ErrorKey: e,
			"errno":         int(e),
		}).Error("ioctl failed")
		return e
	}
	return nil
}
