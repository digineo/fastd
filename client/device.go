package main

import (
	"io"
	"log"
	"os"
	"syscall"
	"time"
)

const SockaddrSize = syscall.SizeofSockaddrInet6

func readPackets() error {
	buf := make([]byte, 1500)

	f, err := os.OpenFile(DevicePath, os.O_RDONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	for {
		i, err := f.Read(buf)
		if err == io.EOF {
			time.Sleep(time.Millisecond * 100)
		} else if err != nil {
			return err
		} else {
			err, msg := parseMessage(buf[:i])
			log.Println("received message:", err, msg)
		}
	}

}
