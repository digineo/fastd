package fastd

import (
	"fmt"
	"syscall"
)

func Stats(key string) {
	val, err := syscall.SysctlUint32(key)
	fmt.Printf("%s=%d %s", key, val, err)
}
