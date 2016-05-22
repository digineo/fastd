package main

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRandomKeypair(t *testing.T) {
	assert := assert.New(t)
	keys := RandomKeypair()
	var zero [KEYSIZE]byte

	assert.NotEqual(keys.public, keys.secret)
	assert.NotEqual(keys.public, zero)
	assert.NotEqual(keys.secret, zero)
}

func TestNewKeyPair(t *testing.T) {
	assert := assert.New(t)

	secret := "800e8ff23adcc5df5f6b911581667821ebecf1ecd95b10b6b5f92f4ebef7704c"
	public := "346a11a8bd8fcedfcde2e19c996b6e4497d0dafc3f5af7096c915bd0f9fe4fe9"
	keys := NewKeyPair(MustDecodeString(secret))

	assert.Equal(public, hex.EncodeToString(keys.public[:]))
}

func TestMakeSharedHandshakeKey(t *testing.T) {
	assert := assert.New(t)
	config.SetServerKey("800e8ff23adcc5df5f6b911581667821ebecf1ecd95b10b6b5f92f4ebef7704c")
	handshakeKey := NewKeyPair(MustDecodeString("a03b6ddf38b693dde2cbefd669ace99c169ca11eae097fb144c5ca9db1cfd176"))

	peer := &Peer{
		publicKey:        MustDecodeString("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2"),
		peerHandshakeKey: MustDecodeString("b4dbdb0c05dd28204534fa27c5afca4dcda5397d833e3064f7a7281b249dc7c7"),
		ourHandshakeKey:  &handshakeKey,
	}

	assert.True(peer.makeSharedHandshakeKey())
	assert.Equal("98a840f7d3845024b6cae090d86eeb72e2607a84ce8ee6ac25639d27e9696596", hex.EncodeToString(peer.sharedKey))
}

func MustDecodeString(str string) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return decoded
}
