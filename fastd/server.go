package fastd

import (
	"fmt"
	"sync"
)

type Server struct {
	peers    map[string]*Peer
	peersMtx sync.Mutex
	impl     ServerImpl
	config   Config
}

type ServerImpl interface {
	Read() chan *Message
	Write(*Message) error
	Close()
}

type ServerBuilder func([]Sockaddr) (ServerImpl, error)

var (
	implementations = map[string]ServerBuilder{
		"udp":    NewUDPServer,
		"kernel": NewKernelServer,
	}
)

func NewServer(implName string, config *Config) (srv *Server, err error) {

	impl := implementations[implName]
	if impl == nil {
		err = fmt.Errorf("unknown implementation: %s", impl)
		return
	}

	// Start implementation
	instance, err := impl(config.Bind)
	if err != nil {
		return
	}

	srv = &Server{
		peers:  make(map[string]*Peer),
		impl:   instance,
		config: *config,
	}

	go srv.worker()

	return
}

func (srv *Server) Stop() {
	srv.impl.Close()
}

// Handle incoming packets
func (srv *Server) worker() {
	for msg := range srv.impl.Read() {
		if reply := srv.handlePacket(msg); reply != nil {
			srv.impl.Write(reply)
		}
	}
}
