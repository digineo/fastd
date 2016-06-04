package fastd

import (
	"fmt"
	"sync"
	"time"
)

type Server struct {
	peers    map[string]*Peer
	peersMtx sync.Mutex
	impl     ServerImpl
	config   Config
	wg       sync.WaitGroup

	timeoutTicker *time.Ticker
	timeoutStop   chan struct{}
}

type ServerImpl interface {
	Read() chan *Message
	Write(*Message) error
	Close()
	Peers() []*Peer
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

		timeoutTicker: time.NewTicker(peerCheckInterval),
		timeoutStop:   make(chan struct{}),
	}

	// Load existing sessions
	for _, peer := range srv.impl.Peers() {
		srv.addPeer(peer)
	}

	srv.startWorker()
	srv.startTimeouter()

	return
}

// Stops all routines
func (srv *Server) Stop() {
	srv.stopTimeouter()
	srv.impl.Close()
	srv.wg.Wait()
}

// Handle incoming packets
func (srv *Server) startWorker() {
	srv.wg.Add(1)
	go func() {
		for msg := range srv.impl.Read() {
			if reply := srv.handlePacket(msg); reply != nil {
				srv.impl.Write(reply)
			}
		}
		srv.wg.Done()
	}()
}
