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
	handshakeKey := NewKeyPair(MustDecodeString("684a0a467306a5a1b727b1b601c9b4157343ce2eda98f5b770ec02d1b0e72668"))

	peer := &Peer{
		publicKey:        MustDecodeString("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2"),
		peerHandshakeKey: MustDecodeString("bbc1151719782317d29ebfb337a7d44d034aff46c1ae930573d398eee8c8efe0"),
		handshakeKey:     &handshakeKey,
	}

	assert.True(makeSharedHandshakeKey(peer))
	assert.Equal("fda6af352d997b984030995772fecbde8b72dd2c8d2845465680162ef931afbf", hex.EncodeToString(peer.sharedKey))
}

func MustDecodeString(str string) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return decoded
}
