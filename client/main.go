package main

import (
	"log"
	"os"
)

var (
	ioctl_CLEAR_BUFFER = _IO('F', 1)
)

func main() {
	log.Println(clearBuffer())
}

func clearBuffer() error {
	f, err := os.OpenFile("/dev/fastd", os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return ioctl(f.Fd(), ioctl_CLEAR_BUFFER, 0)
}
