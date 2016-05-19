package main

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetPublic(t *testing.T) {
	assert := assert.New(t)

	secret := "c05b5c69be567ff1f82598707096bbc63b04a77974f88c334a0d38065180bc7d"
	public := "f9adea6eb454cc8540266b114e21881b917ee120f307a457e96c30c5935b9485"

	assert.Equal(public, hex.EncodeToString(GetPublic(MustDecodeString(secret))))
}

func TestMakeSharedHandshakeKey(t *testing.T) {
	config.SetServerKey("c05b5c69be567ff1f82598707096bbc63b04a77974f88c334a0d38065180bc7d")
	assert := assert.New(t)

	handshakeKey, err := hex.DecodeString("abcd")
	assert.NoError(err)
	assert.NotEmpty(handshakeKey)
	assert.True(makeSharedHandshakeKey(false, handshakeKey))
}

func MustDecodeString(str string) []byte {
	decoded, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return decoded
}
