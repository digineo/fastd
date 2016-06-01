package fastd

import (
	"net"
	"time"
)

type Peer struct {
	Remote           *Sockaddr
	PublicKey        []byte
	sharedKey        []byte
	peerHandshakeKey []byte   // public handshake key from Alice
	ourHandshakeKey  *KeyPair // our handshake key
	handshakeTimeout time.Time

	State  int
	Ifname string
	MTU    uint16
}

func NewPeer(addr *Sockaddr) *Peer {
	return &Peer{
		Remote:          addr,
		ourHandshakeKey: RandomKeypair(),
	}
}

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

func (srv *Server) verifyPeer(peer *Peer) bool {
	if srv.config.VerifyPeer == nil || srv.config.VerifyPeer(peer) {
		peer.handshakeTimeout = time.Now().Add(time.Second * 3)
		return true
	} else {
		return false
	}
}

func (srv *Server) establishPeer(peer *Peer) bool {
	return peer.handshakeTimeout.After(time.Now()) && (srv.config.EstablishPeer == nil || srv.config.EstablishPeer(peer))
}

// Set local and destination address for the PTP interface
func (peer *Peer) SetAddresses(addr, dstaddr net.IP) error {
	return SetAddr(peer.Ifname, addr, dstaddr)
}
