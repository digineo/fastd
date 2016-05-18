package main

import (
	"encoding/hex"
)

type Config struct {
	keySecret []byte
	keyPublic []byte
}

var config = Config{}

// Set the server's key
func (c *Config) SetServerKey(secretHex string) {
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		panic(err)
	}
	if len(secret) != KEYSIZE {
		panic("wrong key size")
	}
	c.keySecret = secret
	c.keyPublic = GetPublic(secret)
}
