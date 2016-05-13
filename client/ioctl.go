package main

import (
	"log"
	"syscall"
)

func ioctl(fd, cmd, ptr uintptr) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, cmd, ptr)
	if e != 0 {
		log.Println("errno=", int(e))
		return e
	}
	return nil
}
