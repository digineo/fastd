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
	config.SetServerKey("800e8ff23adcc5df5f6b911581667821ebecf1ecd95b10b6b5f92f4ebef7704c")
	assert := assert.New(t)

	X := MustDecodeString("bbc1151719782317d29ebfb337a7d44d034aff46c1ae930573d398eee8c8efe0")
	// TODO y/Y berechnen

	assert.True(makeSharedHandshakeKey(false, X))
}

func MustDecodeString(str string) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return decoded
}
