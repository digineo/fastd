package fastd

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/digineo/fastd/ifconfig"
)

// Server is a fastd server.
type Server struct {
	peers    map[string]*Peer // indexed by remote endpoint
	peersMtx sync.RWMutex
	impl     ServerImpl
	config   Config
	wg       sync.WaitGroup

	timeoutTicker *time.Ticker
	timeoutStop   chan struct{}
}

// ServerImpl is the common interface for UDP and Kernel servers.
type ServerImpl interface {
	Read() chan *Message  // returns the channel for incoming messages
	Write(*Message) error // sends a message
	Close()               // closes the server
	Peers() []*Peer       // returns list of existing peers
}

// ServerBuilder is a func returning a server implementation. Known
// server builders are NewUDPServer and NewKernelServer.
type ServerBuilder func([]Sockaddr) (ServerImpl, error)

// TODO: use constants
var implementations = map[string]ServerBuilder{
	"udp":    NewUDPServer,
	"kernel": NewKernelServer,
}

// NewServer constructs and starts a new server instance. implName must
// be either one of "udp" or "kernel".
func NewServer(implName string, config *Config) (srv *Server, err error) {
	impl := implementations[implName]
	if impl == nil {
		err = fmt.Errorf("unknown implementation: %v", impl)
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

	// Load existing sessions
	for _, peer := range srv.impl.Peers() {
		if peer.Remote.Port > 0 {
			srv.addPeer(peer)
		} else {
			// session not established
			log.Println("destroying unestablished session", peer.Ifname)
			ifconfig.Destroy(peer.Ifname)
		}
	}

	srv.startWorker()

	if srv.config.Timeout > 0 {
		srv.timeoutTicker = time.NewTicker(peerCheckInterval)
		srv.timeoutStop = make(chan struct{})
		srv.startTimeouter()
	}

	return
}

// Stop stopps all routines
func (srv *Server) Stop() {
	if srv.timeoutTicker != nil {
		srv.stopTimeouter()
	}
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
