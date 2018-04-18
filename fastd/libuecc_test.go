package fastd

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
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
	keys := DecodeKeyPair(secret)

	assert.Equal(public, hex.EncodeToString(keys.public[:]))
}

func TestMakeRespondingSharedHandshakeKey(t *testing.T) {
	assert := assert.New(t)
	peerKey := MustDecodeHex("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2")

	hs := &Handshake{
		peerHandshakeKey: MustDecodeHex("b4dbdb0c05dd28204534fa27c5afca4dcda5397d833e3064f7a7281b249dc7c7"),
		ourHandshakeKey:  DecodeKeyPair("a03b6ddf38b693dde2cbefd669ace99c169ca11eae097fb144c5ca9db1cfd176"),
	}

	assert.True(hs.makeSharedKey(false, testServerSecret, peerKey))
	assert.Equal("98a840f7d3845024b6cae090d86eeb72e2607a84ce8ee6ac25639d27e9696596", hex.EncodeToString(hs.sharedKey))
}

func TestMakeInitiatingSharedHandshakeKey(t *testing.T) {
	assert := assert.New(t)
	peerKey := MustDecodeHex("346a11a8bd8fcedfcde2e19c996b6e4497d0dafc3f5af7096c915bd0f9fe4fe9")

	hs := &Handshake{
		peerHandshakeKey: MustDecodeHex("3bac2ada2fbfa1ea75b2cb214490d5d718f1bbe5b226184488c07cf1a551e8d9"),
		ourHandshakeKey:  DecodeKeyPair("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e5f"),
	}

	assert.True(hs.makeSharedKey(true, testClientSecret, peerKey))
	assert.Equal("d5d652897baf38d7947921e167288a0fb2e8c32edb5f9efd56e34aa574d5fac9", hex.EncodeToString(hs.sharedKey))
}

func MustDecodeHex(str string) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return decoded
}

func DecodeKeyPair(str string) *KeyPair {
	return NewKeyPair(MustDecodeHex(str))
}
