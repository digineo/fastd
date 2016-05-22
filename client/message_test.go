package main

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"testing"
)

func TestParseRequest(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-request.dat")

	msg, err := ParseMessage(bytes, true)
	assert.Nil(err)
	assert.NotNil(msg)

	assert.Equal("127.0.0.1", msg.Src.IP.String())
	assert.Equal(8755, int(msg.Src.Port))
	assert.Equal(7, len(msg.Records))

	// Handshake type
	assert.Equal([]byte{1}, msg.Records[RECORD_HANDSHAKE_TYPE])

	// Protocol name
	assert.Equal("ec25519-fhmqvc", string(msg.Records[RECORD_PROTOCOL_NAME]))

	// Recipient Key
	assert.Equal("346a11a8bd8fcedfcde2e19c996b6e4497d0dafc3f5af7096c915bd0f9fe4fe9", hex.EncodeToString(msg.Records[RECORD_RECIPIENT_KEY]))

	// Sender Key
	assert.Equal("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2", hex.EncodeToString(msg.Records[RECORD_SENDER_KEY]))

	// Sender Handshake Key
	assert.Equal("7a3f787a77899215b21b932714f32dab8735f844036eafa4ab67e981c6df65fa", hex.EncodeToString(msg.Records[RECORD_SENDER_HANDSHAKE_KEY]))

	// Marshaling
	assert.Equal(len(bytes), len(msg.Marshal(true)))

	// Parse marshaled message
	msg2, err := ParseMessage(msg.Marshal(true), true)
	assert.Nil(err)
	assert.NotNil(msg2)
	//assert.EqualValues(msg.Marshal(), msg2.Marshal())
}

func TestVerifySignature(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-finish.dat")

	msg, err := ParseMessage(bytes, true)
	assert.Nil(err)
	assert.NotNil(msg)

	// Without signing key
	assert.False(msg.VerifySignature())

	// Invalid siging key
	msg.SignKey = MustDecodeString("bd3bd258df61fa369d1bf003a8a3ccb2f08a8931bf8add78eddaefbc1defc5b5")
	assert.False(msg.VerifySignature())

	// Valid signing key
	msg.SignKey = MustDecodeString("1def4def54cfccdc536fc741306a3fbe78ae61a591bc7d7978f96329832bd22d")
	assert.True(msg.VerifySignature())
}

func TestHandleMessage(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-request.dat")

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
