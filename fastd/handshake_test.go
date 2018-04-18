package fastd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHandshake(t *testing.T) {
	assert := assert.New(t)
	peerAddr := Sockaddr{IP: net.ParseIP("127.0.0.1"), Port: 8755}

	srv := Server{}
	srv.config.serverKeys = testServerSecret
	srv.peers = make(map[string]*Peer)

	peer := srv.GetPeer(peerAddr)
	assert.Nil(peer.handshake)

	// Handshake request (0x01)
	msg := readTestmsg("null-request.dat")

	// Handle request and build response (0x02)
	reply := srv.handlePacket(msg)
	assert.NotNil(reply)
	assert.NotNil(reply.SignKey)
	assert.NotNil(peer.handshake)
	assert.Equal([]byte{2}, reply.Records[RecordHandshakeType])
	assert.Equal([]byte{0}, reply.Records[RecordReplyCode])
	assert.Equal(msg.Records[RecordSenderKey], reply.Records[RecordRecipientKey])
	assert.Equal(msg.Records[RecordProtocolName], reply.Records[RecordProtocolName])

	// Handshake finish (0x03)
	msg = readTestmsg("null-finish.dat")

	// Handle finish
	reply = srv.handlePacket(msg)
	assert.Nil(reply)
}
