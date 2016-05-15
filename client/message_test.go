package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParseMessage(t *testing.T) {
	assert := assert.New(t)

	bytes, err := ioutil.ReadFile("testdata/null-cipher.dat")
	assert.Nil(err)
	assert.NotNil(bytes)

	msg, err := parseMessage(bytes)
	assert.Nil(err)
	assert.NotNil(msg)

	assert.Equal("127.0.0.1", msg.Address.String())
	assert.Equal(19800, int(msg.Port))
	assert.Equal(7, len(msg.Packet.Records))

	// Handshake type
	assert.Equal([]byte{1}, msg.Packet.Records[0x0000])

	// Protocol name
	assert.Equal("ec25519-fhmqvc", string(msg.Packet.Records[0x0005]))

	// Sender key
	assert.Equal(32, len(msg.Packet.Records[0x0006]))

	// Marshaling
	assert.Equal(len(bytes), len(msg.Marshal()))

	// Parse marshaled message
	msg2, err := parseMessage(msg.Marshal())
	assert.Nil(err)
	assert.NotNil(msg2)
	assert.EqualValues(msg.Marshal(), msg2.Marshal())
}
