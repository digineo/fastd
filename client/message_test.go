package main

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParseMessage(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-cipher.dat")

	msg, err := parseMessage(bytes)
	assert.Nil(err)
	assert.NotNil(msg)

	assert.Equal("127.0.0.1", msg.Src.IP.String())
	assert.Equal(8755, int(msg.Src.Port))
	assert.Equal(7, len(msg.Records))

	// Handshake type
	assert.Equal([]byte{1}, msg.Records[RECORD_HANDSHAKE_TYPE])

	// Protocol name
	assert.Equal("ec25519-fhmqvc", string(msg.Records[RECORD_PROTOCOL_NAME]))

	// Sender key
	assert.Equal(32, len(msg.Records[RECORD_SENDER_KEY]))

	// Marshaling
	assert.Equal(len(bytes), len(msg.Marshal(nil)))

	// Parse marshaled message
	msg2, err := parseMessage(msg.Marshal(nil))
	assert.Nil(err)
	assert.NotNil(msg2)
	//assert.EqualValues(msg.Marshal(), msg2.Marshal())
}

func TestHandleMessage(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-cipher.dat")

	msg, err := parseMessage(bytes)
	assert.Nil(err)
	assert.NotNil(msg)

	handlePacket(msg)
}

func readTestdata(name string) []byte {
	bytes, err := ioutil.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return bytes
}
