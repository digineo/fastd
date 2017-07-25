package fastd

import (
	"encoding/hex"
	"fmt"
	"time"
)

// Config is the configuration of a fastd server instance
type Config struct {
	Bind            []Sockaddr
	serverKeys      *KeyPair
	Timeout         time.Duration
	AssignAddresses func(*Peer)
	OnVerify        func(*Peer) error
	OnEstablished   func(*Peer)
	OnTimeout       func(*Peer)
}

// SetServerKey sets the server's key
func (c *Config) SetServerKey(secretHex string) error {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return fmt.Errorf("unable to decode secret: %s", err)
	}
	if len(secret) != KEYSIZE {
		return fmt.Errorf("wrong secret size: expected=%d actual=%d", KEYSIZE, len(secret))
	}
	c.serverKeys = NewKeyPair(secret)
	return nil
}
