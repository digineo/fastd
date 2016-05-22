package main

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestHandshake(t *testing.T) {
	assert := assert.New(t)
	config.SetServerKey("800e8ff23adcc5df5f6b911581667821ebecf1ecd95b10b6b5f92f4ebef7704c")
	var (
		srcAddr          = &Sockaddr{IP: net.ParseIP("127.0.0.1"), Port: 51231}
		protocolName     = []byte("ec25519-fhmqvc")
		methodName       = []byte("null")
		handshakeKey     = NewKeyPair(MustDecodeString("a03b6ddf38b693dde2cbefd669ace99c169ca11eae097fb144c5ca9db1cfd176"))
		peerKey          = MustDecodeString("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2")
		peerHandshakeKey = MustDecodeString("b4dbdb0c05dd28204534fa27c5afca4dcda5397d833e3064f7a7281b249dc7c7")
	)

	// Handshake request (0x01)
	msg := NewMessage()
	msg.Src = srcAddr
	msg.Records[RECORD_HANDSHAKE_TYPE] = []byte{1}
	msg.Records[RECORD_RECIPIENT_KEY] = config.serverKeys.public[:]
	msg.Records[RECORD_PROTOCOL_NAME] = protocolName
	msg.Records[RECORD_METHOD_NAME] = methodName
	msg.Records[RECORD_SENDER_KEY] = peerKey
	msg.Records[RECORD_SENDER_HANDSHAKE_KEY] = peerHandshakeKey

	// Handle request and build response (0x02)
	reply := handlePacket(msg)
	assert.NotNil(reply)
	assert.NotNil(reply.SignKey)
	assert.Equal([]byte{2}, reply.Records[RECORD_HANDSHAKE_TYPE])
	assert.Equal([]byte{0}, reply.Records[RECORD_REPLY_CODE])
	assert.Equal(msg.Records[RECORD_SENDER_KEY], reply.Records[RECORD_RECIPIENT_KEY])
	assert.Equal(msg.Records[RECORD_PROTOCOL_NAME], reply.Records[RECORD_PROTOCOL_NAME])

	// Handshake finish (0x03)
	msg = NewMessage()
	msg.Src = srcAddr
	msg.Records[RECORD_HANDSHAKE_TYPE] = []byte{3}
	msg.Records[RECORD_RECIPIENT_KEY] = config.serverKeys.public[:]
	msg.Records[RECORD_RECIPIENT_HANDSHAKE_KEY] = handshakeKey.public[:]
	msg.Records[RECORD_PROTOCOL_NAME] = []byte("ec25519-fhmqvc")
	msg.Records[RECORD_SENDER_KEY] = peerKey
	msg.Records[RECORD_SENDER_HANDSHAKE_KEY] = peerHandshakeKey

	// Handle finish
	reply = handlePacket(msg)
	assert.NotNil(reply)
}
