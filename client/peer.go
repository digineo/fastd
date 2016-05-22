package main

type Peer struct {
	publicKey        []byte
	sharedKey        []byte
	peerHandshakeKey []byte   // public handshake key from Alice
	ourHandshakeKey  *KeyPair // our handshake key

	State  int
	Ifname string
	MTU    uint16
}
