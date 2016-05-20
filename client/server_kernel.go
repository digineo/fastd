package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const (
	DevicePath = "/dev/fastd"
)

type KernelServer struct {
	dev  *os.File      // Interface to kernel
	recv chan *Message // Received messages
}

func NewKernelServer(listenAddr net.IP, listenPort uint16) (Server, error) {
	dev, err := os.OpenFile(DevicePath, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	// close listening socket
	ioctl(dev.Fd(), ioctl_CLOSE, 0)

	// create new socket
	addr := sockaddrToRaw(listenAddr, listenPort)
	err = ioctl(dev.Fd(), ioctl_BIND, uintptr(addr))
	if err != nil {
		return nil, err
	}

	srv := &KernelServer{
		dev:  dev,
		recv: make(chan *Message, 10),
	}

	go srv.readPackets()

	return srv, nil
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
			if err = srv.read(buf[:n]); err != nil {
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
	bytes := msg.Marshal(nil, true)
	i, err := srv.dev.Write(bytes)
	log.Println("send:", bytes)
	log.Println("written:", i, err)
	return err
}
