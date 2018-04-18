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
	assert.Equal([]byte{byte(HandshakeReply)}, reply.Records[RecordHandshakeType])
	assert.Equal([]byte{byte(ReplySuccess)}, reply.Records[RecordReplyCode])
	assert.Equal(msg.Records[RecordSenderKey], reply.Records[RecordRecipientKey])
	assert.Equal(msg.Records[RecordProtocolName], reply.Records[RecordProtocolName])

	typ, err := reply.Records.HandshakeType()
	assert.NoError(err)
	assert.Equal(HandshakeReply, typ)

	code, err := reply.Records.ReplyCode()
	assert.NoError(err)
	assert.Equal(ReplySuccess, code)

	lkey, err := msg.Records.SenderKey()
	assert.NoError(err)
	rkey, err := reply.Records.RecipientKey()
	assert.NoError(err)
	assert.Equal(lkey, rkey)

	lproto, err := msg.Records.ProtocolName()
	assert.NoError(err)
	rproto, err := reply.Records.ProtocolName()
	assert.NoError(err)
	assert.Equal(lproto, rproto)

	// Handshake finish (0x03)
	msg = readTestmsg("null-finish.dat")

	// Handle finish
	reply = srv.handlePacket(msg)
	assert.Nil(reply)
}
