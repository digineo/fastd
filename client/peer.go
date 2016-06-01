package main

import (
	"net"
	"sync"
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

var (
	peers         map[string]*Peer
	peersMtx      sync.Mutex
	VerifyPeer    func(*Peer) bool
	EstablishPeer func(*Peer) bool
)

func InitPeers() {
	peers = make(map[string]*Peer)
	VerifyPeer = func(*Peer) bool {
		return true
	}
	EstablishPeer = func(*Peer) bool {
		return true
	}
}

func NewPeer(addr *Sockaddr) *Peer {
	return &Peer{
		Remote:          addr,
		ourHandshakeKey: RandomKeypair(),
	}
}

func GetPeer(addr *Sockaddr) (peer *Peer) {
	key := string(addr.Raw())

	peersMtx.Lock()
	defer peersMtx.Unlock()

	if peer, _ = peers[key]; peer == nil {
		peer = NewPeer(addr)
		peers[key] = peer
	}
	return
}

func verifyPeer(peer *Peer) bool {
	if VerifyPeer(peer) {
		peer.handshakeTimeout = time.Now().Add(time.Second * 3)
		return true
	} else {
		return false
	}
}

func establishPeer(peer *Peer) bool {
	return peer.handshakeTimeout.After(time.Now()) && VerifyPeer(peer)
}

// Set local and destination address for the PTP interface
func (peer *Peer) SetAddresses(addr, dstaddr net.IP) error {
	return SetAddr(peer.Ifname, addr, dstaddr)
}
