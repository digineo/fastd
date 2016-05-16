package main

import (
	"io"
	"log"
	"os"
	"syscall"
	"time"
)

const SockaddrSize = syscall.SizeofSockaddrInet6

var dev *os.File

type Device struct {
	f os.File
}

func OpenDevice() error {
	var err error
	dev, err = os.OpenFile(DevicePath, os.O_RDWR, 0644)
	return err
}

func CloseDevice() {
	if dev != nil {
		dev.Close()
	}
}

func bind() error {
	addr := sockaddrToRaw(listenAddr, listenPort)
	return ioctl(dev.Fd(), ioctl_BIND, uintptr(addr))
}

func close() error {
	return ioctl(dev.Fd(), ioctl_CLOSE, 0)
}

func readPackets() error {
	buf := make([]byte, 1500)

	for {
		i, err := dev.Read(buf)
		if err == io.EOF {
			time.Sleep(time.Millisecond * 100)
		} else if err != nil {
			return err
		} else {
			log.Println(buf[:i])
			msg, err := parseMessage(buf[:i])
			log.Println("received message:", err, msg)

			writePaket(msg.NewReply(0x02))
		}
	}
}

func writePaket(msg *Message) error {
	bytes := msg.Marshal(nil)
	i, err := dev.Write(bytes)
	log.Println("send:", bytes)
	log.Println("written:", i, err)
	return err
}
