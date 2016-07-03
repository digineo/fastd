package fastd

import (
	"encoding/hex"
	"fmt"
	"time"
)

type Config struct {
	Bind            []Sockaddr
	serverKeys      *KeyPair
	Timeout         time.Duration
	AssignAddresses func(*Peer)
	OnVerify        func(*Peer) bool
	OnEstablish     func(*Peer) bool
	OnDisestablish  func(*Peer)
}

// Set the server's key
func (c *Config) SetServerKey(secretHex string) error {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return fmt.Errorf("unable to decode secret:", secretHex)
	}
	if len(secret) != KEYSIZE {
		return fmt.Errorf("wrong secret size: expected=%d actual=%d", KEYSIZE, len(secret))
	}
	c.serverKeys = NewKeyPair(secret)
	return nil
}
