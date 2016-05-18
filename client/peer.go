package main

type Peer struct {
	PublicKey          []byte
	SharedHandshakeKey []byte
	Sigma              []byte

	State  int
	Ifname string
	MTU    uint16
}
