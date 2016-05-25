package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	DevicePath = "/dev/fastd"
)

type KernelServer struct {
	dev       *os.File      // Interface to kernel
	recv      chan *Message // Received messages
	addresses []Sockaddr
}

func NewKernelServer(addresses []Sockaddr) (Server, error) {
	dev, err := os.OpenFile(DevicePath, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	srv := &KernelServer{
		dev:  dev,
		recv: make(chan *Message, 10),
	}

	for _, address := range addresses {
		if err = srv.ioctl(ioctl_CLOSE, address); err != nil && err != syscall.ENXIO {
			log.Println("ioctl close failed", err)
		}
		if err = srv.ioctl(ioctl_BIND, address); err != nil {
			log.Println("ioctl bind failed", err)
			srv.Close()
			return nil, err
		}
		srv.addresses = append(srv.addresses, address)
	}

	go srv.readPackets()

	return srv, nil
}

func (srv *KernelServer) ioctl(cmd uintptr, addr Sockaddr) error {
	sa := addr.RawFixed()
	return ioctl(srv.dev.Fd(), cmd, uintptr(unsafe.Pointer(&sa)))
}

func (srv *KernelServer) Read() chan *Message {
	return srv.recv
}

func (srv *KernelServer) Close() {
	if srv.dev != nil {
		srv.dev.Close()
	}
	close(srv.recv)
}

func (srv *KernelServer) readPackets() error {
	buf := make([]byte, 1500)

	for {
		n, err := srv.dev.Read(buf)
		if err == io.EOF {
			time.Sleep(time.Millisecond * 100)
		} else if err != nil {
			return err
		} else {
			data := make([]byte, n)
			copy(data, buf[:n])
			if err = srv.read(data); err != nil {
				log.Println(err)
			}
		}
	}
}

func (srv *KernelServer) read(buf []byte) error {
	// check size
	if len(buf) < 40 {
		return fmt.Errorf("packet too small (%d bytes)", len(buf))
	}

	if msg, err := ParseMessage(buf, true); err != nil {
		return fmt.Errorf("unmarshal failed: %v", err)
	} else {
		srv.recv <- msg
		return nil
	}
}

func (srv *KernelServer) Write(msg *Message) error {
	bytes := msg.Marshal(true)
	i, err := srv.dev.Write(bytes)
	log.Println("send:", bytes)
	log.Println("written:", i, err)
	return err
}
