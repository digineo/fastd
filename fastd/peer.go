package fastd

import (
	"log"
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
	lastSeen         time.Time

	Ifname   string
	MTU      uint16
	ipackets uint64 // received packet counter
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

// Returns true if the counter has been updated
func (peer *Peer) updateCounter() bool {
	stats, err := GetStats(peer.Ifname)
	if err != nil {
		log.Println("Unable to get stats for %s: %s", peer.Ifname, err)
		return false
	}

	// packet counter changed?
	if peer.ipackets != stats.ipackets {
		peer.ipackets = stats.ipackets
		peer.lastSeen = time.Now()
		return true
	}

	return false
}

// Returns whether the peer is timed out
func (peer *Peer) hasTimeout() bool {
	if peer.Ifname != "" && peer.updateCounter() {
		return false
	}

	return peer.lastSeen.Add(time.Minute).After(time.Now())
}

// Removes timed out peers
func (srv *Server) timeoutPeers() {
	srv.peersMtx.Lock()
	defer srv.peersMtx.Unlock()

	for _, peer := range srv.peers {
		if peer.hasTimeout() {
			// TODO remove peer
		}
	}
}
