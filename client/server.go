package main

import (
	"net"
)

type Server interface {
	Read() chan *Message
	Write(*Message) error
	Close()
}

type ServerFactory func(net.IP, uint16) (Server, error)
