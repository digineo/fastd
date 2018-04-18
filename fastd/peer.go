package fastd

import (
	"log"
	"net"
	"time"

	"github.com/digineo/fastd/ifconfig"
)

// AddressConfig contains the local and remote PTP address
type AddressConfig struct {
	LocalAddr net.IP // local PTP address
	DestAddr  net.IP // remote PTP address
}

// Peer is a fastd peer
type Peer struct {
	Remote    Sockaddr
	PublicKey []byte
	handshake *Handshake // handshake until it's finished
	lastSeen  time.Time

	Ifname   string
	MTU      uint16
	IPv4     AddressConfig
	IPv6     AddressConfig
	ipackets uint64 // received packet counter

	Vars []byte      // Vars that is sent to the client
	Data interface{} // Some data that can be attached to the peer
}

// NewPeer initializes a new Peer struct
func NewPeer(addr Sockaddr) *Peer {
	return &Peer{
		Remote:   addr,
		lastSeen: time.Now(),
	}
}

// PeersCount returns the number of known peers
func (srv *Server) PeersCount() int {
	srv.peersMtx.RLock()
	defer srv.peersMtx.RUnlock()
	return len(srv.peers)
}

// GetPeers returns all peers
func (srv *Server) GetPeers() []*Peer {
	srv.peersMtx.RLock()
	defer srv.peersMtx.RUnlock()

	i := 0
	peers := make([]*Peer, len(srv.peers))
	for _, peer := range srv.peers {
		peers[i] = peer
		i++
	}

	return peers
}

// GetPeer returns the peer and creates it if it does not exist yet
func (srv *Server) GetPeer(addr Sockaddr) (peer *Peer) {
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

// Calls the OnVerify hook (if exists) and sets the handshake timeout
func (srv *Server) verifyPeer(peer *Peer) error {
	// Call OnVerify hook
	if f := srv.config.OnVerify; f != nil {
		if err := f(peer); err != nil {
			return err
		}
	}

	// Set the handshake timeout
	if hs := peer.handshake; hs != nil {
		hs.timeout = time.Now().Add(time.Second * 3)
	}
	return nil
}

// checks the handshake timeout
func (srv *Server) establishPeer(peer *Peer) bool {
	hs := peer.handshake
	if hs == nil {
		return false
	}
	return hs.timeout.After(time.Now())
}

// RemovePeer removes (disconnects) a peer
func (srv *Server) RemovePeer(peer *Peer) {
	srv.peersMtx.Lock()
	srv.removePeerLocked(peer)
	srv.peersMtx.Unlock()
}

// Removes a peer and its interface
func (srv *Server) removePeerLocked(peer *Peer) {
	if peer.Ifname != "" {
		ifconfig.Destroy(peer.Ifname)
	}
	delete(srv.peers, string(peer.Remote.Raw()))
}

// Assign tunnel addresses
func (peer *Peer) assignAddresses() {
	peer.IPv4.Assign(peer.Ifname)
	peer.IPv6.Assign(peer.Ifname)
}

// Assign local and destination address to the PTP interface
func (config *AddressConfig) Assign(ifname string) {
	if config.LocalAddr == nil || config.DestAddr == nil {
		return
	}
	if err := SetAddrPTP(ifname, config.LocalAddr, config.DestAddr); err != nil {
		log.Printf("Setting addresses for %s failed: %s", ifname, err)
	}
}
