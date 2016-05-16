package main

type Peer struct {
	PublicKey    []byte
	HandshakeKey []byte

	State  int
	Ifname string
	MTU    uint16
}
