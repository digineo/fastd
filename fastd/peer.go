package fastd

import (
	"github.com/digineo/fastd/ifconfig"
	"net"
	"time"
)

type AddressConfig struct {
	LocalAddr net.IP // local PTP address
	DestAddr  net.IP // remote PTP address
}

type Peer struct {
	Remote           *Sockaddr
	PublicKey        []byte
	sharedKey        []byte
	peerHandshakeKey []byte   // public handshake key from Alice
	ourHandshakeKey  *KeyPair // our handshake key
	handshakeTimeout time.Time
	lastSeen         time.Time

	Ifname   string
	MTU      uint16
	IPv4     AddressConfig
	IPv6     AddressConfig
	ipackets uint64 // received packet counter

	Vars []byte      // Vars that is sent to the client
	Data interface{} // Some data that can be attached to the peer
}

func NewPeer(addr *Sockaddr) *Peer {
	return &Peer{
		Remote:          addr,
		ourHandshakeKey: RandomKeypair(),
		lastSeen:        time.Now(),
	}
}

// Returns the peer and creates it if it does not exist yet
func (srv *Server) GetPeer(addr *Sockaddr) (peer *Peer) {
	key := string(addr.Raw())

	srv.peersMtx.Lock()
	defer srv.peersMtx.Unlock()

	if peer, _ = srv.peers[key]; peer == nil {
		peer = NewPeer(addr)
		srv.peers[key] = peer
	}
	return
}

// Adds a peer to the internal map without any verification
func (srv *Server) addPeer(in *Peer) {
	key := string(in.Remote.Raw())

	peer := NewPeer(in.Remote)
	peer.Ifname = in.Ifname
	peer.PublicKey = in.PublicKey
	srv.peers[key] = peer

	return
}

func (srv *Server) verifyPeer(peer *Peer) bool {
	if srv.config.OnVerify == nil || srv.config.OnVerify(peer) {
		peer.handshakeTimeout = time.Now().Add(time.Second * 3)
		return true
	} else {
		return false
	}
}

func (srv *Server) establishPeer(peer *Peer) bool {
	return peer.handshakeTimeout.After(time.Now()) && (srv.config.OnEstablish == nil || srv.config.OnEstablish(peer))
}

// Removes a peer and its interface
func (srv *Server) removePeerLocked(peer *Peer) {
	if peer.Ifname != "" {
		ifconfig.Destroy(peer.Ifname)
	}
	delete(srv.peers, string(peer.Remote.Raw()))
}

// Set local and destination address for the PTP interface
func (peer *Peer) SetAddresses(config AddressConfig) error {
	if config.LocalAddr != nil && config.DestAddr != nil {
		return SetAddr(peer.Ifname, config.LocalAddr, config.DestAddr)
	} else {
		return nil
	}
}
