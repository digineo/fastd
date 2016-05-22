package main

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestHandshake(t *testing.T) {
	assert := assert.New(t)
	config.SetServerKey("800e8ff23adcc5df5f6b911581667821ebecf1ecd95b10b6b5f92f4ebef7704c")

	msg := NewMessage()
	msg.Src = &Sockaddr{IP: net.ParseIP("127.0.0.1"), Port: 51231}
	msg.Records[RECORD_HANDSHAKE_TYPE] = []byte{1}
	msg.Records[RECORD_RECIPIENT_KEY] = config.serverKeys.public[:]
	msg.Records[RECORD_PROTOCOL_NAME] = []byte("ec25519-fhmqvc")
	//msg.Records[RECORD_MTU] =
	msg.Records[RECORD_SENDER_KEY] = MustDecodeString("83369beddca777585167520fb54a7fb059102bf4e0a46dd5fb1c633d83db77a2")
	msg.Records[RECORD_SENDER_HANDSHAKE_KEY] = MustDecodeString("b4dbdb0c05dd28204534fa27c5afca4dcda5397d833e3064f7a7281b249dc7c7")

	reply := handlePacket(msg)
	assert.NotNil(reply)
	assert.NotNil(reply.signKey)
	assert.Equal([]byte{2}, reply.Records[RECORD_HANDSHAKE_TYPE])
	assert.Equal([]byte{0}, reply.Records[RECORD_REPLY_CODE])
	assert.Equal(msg.Records[RECORD_SENDER_KEY], reply.Records[RECORD_RECIPIENT_KEY])
	assert.Equal(msg.Records[RECORD_SENDER_KEY], reply.Records[RECORD_RECIPIENT_KEY])
	assert.Equal(msg.Records[RECORD_PROTOCOL_NAME], reply.Records[RECORD_PROTOCOL_NAME])
}
