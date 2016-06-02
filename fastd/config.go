package fastd

import (
	"encoding/hex"
)

type Config struct {
	Bind           []Sockaddr
	serverKeys     *KeyPair
	OnVerify       func(*Peer) bool
	OnEstablish    func(*Peer) bool
	OnDisestablish func(*Peer)
}

// Set the server's key
func (c *Config) SetServerKey(secretHex string) {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		panic(err)
	}
	if len(secret) != KEYSIZE {
		panic("wrong key size")
	}
	c.serverKeys = NewKeyPair(secret)
}
