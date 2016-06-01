package fastd

/*
#include <net/if.h>
*/
import "C"

import (
	"log"
	"syscall"
	"unsafe"
)

var (
	ioctl_LIST          = _IO('F', 1)
	ioctl_BIND          = _IOW('F', 2, 18)
	ioctl_CLOSE         = _IOW('F', 3, 18)
	ioctl_SIOCDIFADDR   = _IOW('i', 25, unsafe.Sizeof(C.struct_ifreq{}))      // delete IF addr
	ioctl_SIOCAIFADDR   = _IOW('i', 43, unsafe.Sizeof(C.struct_ifaliasreq{})) // add/chg IF alias
	ioctl_SIOCIFCREATE  = _IOWR('i', 122, unsafe.Sizeof(C.struct_ifreq{}))    // create clone if
	ioctl_SIOCIFCREATE2 = _IOWR('i', 124, unsafe.Sizeof(C.struct_ifreq{}))    // create clone if
	ioctl_SIOCIFDESTROY = _IOW('i', 121, unsafe.Sizeof(C.struct_ifreq{}))     // destroy clone if
	ioctl_SET_DRV_SPEC  = _IOW('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))
	ioctl_GET_DRV_SPEC  = _IOWR('i', 123, unsafe.Sizeof(C.struct_ifdrv{}))
)

func ioctl(fd, cmd, ptr uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, ptr)
	if e != 0 {
		log.Printf("errno=%d %s", int(e), e)
		return e
	}
	return nil
}
