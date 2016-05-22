package main

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParseMessage(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-cipher.dat")

	msg, err := ParseMessage(bytes, true)
	assert.Nil(err)
	assert.NotNil(msg)

	assert.Equal("127.0.0.1", msg.Src.IP.String())
	assert.Equal(8755, int(msg.Src.Port))
	assert.Equal(8, len(msg.Records))

	// Handshake type
	assert.Equal([]byte{1}, msg.Records[RECORD_HANDSHAKE_TYPE])

	// Protocol name
	assert.Equal("ec25519-fhmqvc", string(msg.Records[RECORD_PROTOCOL_NAME]))

	// Recipient Key
	assert.Equal("346a11a8bd8fcedfcde2e19c996b6e4497d0dafc3f5af7096c915bd0f9fe4fe9", hex.EncodeToString(msg.Records[RECORD_RECIPIENT_KEY]))

	// Sender Key
	assert.Equal("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2", hex.EncodeToString(msg.Records[RECORD_SENDER_KEY]))

	// Sender Handshake Key
	assert.Equal("bbc1151719782317d29ebfb337a7d44d034aff46c1ae930573d398eee8c8efe0", hex.EncodeToString(msg.Records[RECORD_SENDER_HANDSHAKE_KEY]))

	// Marshaling
	assert.Equal(len(bytes), len(msg.Marshal(true)))

	// Parse marshaled message
	msg2, err := ParseMessage(msg.Marshal(true), true)
	assert.Nil(err)
	assert.NotNil(msg2)
	//assert.EqualValues(msg.Marshal(), msg2.Marshal())
}

func TestHandleMessage(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-cipher.dat")

	msg, err := ParseMessage(bytes, true)
	assert.Nil(err)
	assert.NotNil(msg)

	resp := handlePacket(msg)
	assert.NotNil(resp)
}

func readTestdata(name string) []byte {
	bytes, err := ioutil.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return bytes
}
