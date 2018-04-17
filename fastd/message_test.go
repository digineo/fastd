package fastd

import (
	"encoding/hex"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	// Keys for the captured testdata
	testServerSecret = DecodeKeyPair("800e8ff23adcc5df5f6b911581667821ebecf1ecd95b10b6b5f92f4ebef7704c")
	testClientSecret = DecodeKeyPair("d82638e3bf436fe92c54649c33aca36064534d4171d7746b7ee36c822b8da149")
	testSharedKey    = MustDecodeHex("08d845c98084f16cb9d21f6a2d5c270de008ed6faa0f81fa0071360296e227f2")
)

func TestParseRequest(t *testing.T) {
	assert := assert.New(t)
	bytes := readTestdata("null-request.dat")

	msg, err := ParseMessage(bytes, true)
	assert.Nil(err)
	assert.NotNil(msg)

	assert.Equal("127.0.0.1", msg.Src.IP.String())
	assert.Equal(8755, int(msg.Src.Port))
	assert.Equal(int(RECORD_MAX), len(msg.Records))

	// Handshake type
	assert.Equal([]byte{1}, msg.Records[RECORD_HANDSHAKE_TYPE])

	// Protocol name
	assert.Equal("ec25519-fhmqvc", string(msg.Records[RECORD_PROTOCOL_NAME]))

	// Recipient Key
	assert.Equal(hex.EncodeToString(testServerSecret.public[:]), hex.EncodeToString(msg.Records[RECORD_RECIPIENT_KEY]))

	// Sender Key
	assert.Equal("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2", hex.EncodeToString(msg.Records[RECORD_SENDER_KEY]))

	// Sender Handshake Key
	assert.Equal("2d25af50e5beab86fa0014caa5a06a32afca1f3467499c5dbdc252e74d95ee90", hex.EncodeToString(msg.Records[RECORD_SENDER_HANDSHAKE_KEY]))

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
	msg.SignKey = MustDecodeHex("bd3bd258df61fa369d1bf003a8a3ccb2f08a8931bf8add78eddaefbc1defc5b5")
	assert.False(msg.VerifySignature())

	// Valid signing key
	msg.SignKey = testSharedKey
	assert.True(msg.VerifySignature())
}

func readTestdata(name string) []byte {
	bytes, err := ioutil.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return bytes
}

func readTestmsg(name string) *Message {
	msg, err := ParseMessage(readTestdata(name), true)
	if err != nil {
		panic(err)
	}
	return msg
}
