package main

type Server interface {
	Read() chan *Message
	Write(*Message) error
	Close()
}

type ServerFactory func([]Sockaddr) (Server, error)
