package fastd

import (
	"bytes"
	"log"
	"net"
	"reflect"
	"time"
)

func (srv *Server) handlePacket(msg *Message) (reply *Message) {
	records := msg.Records

	log.Printf("received handshake from %s[%d] using fastd %s", msg.Src.IP.String(), msg.Src.Port, records[RECORD_VERSION_NAME])

	senderKey := records[RECORD_SENDER_KEY]
	recipientKey := records[RECORD_RECIPIENT_KEY]
	senderHandshakeKey := records[RECORD_SENDER_HANDSHAKE_KEY]

	if reflect.DeepEqual(msg.Src, msg.Dst) {
		log.Println("source address equals destination address")
		return
	}

	reply = msg.NewReply()

	if recipientKey == nil {
		log.Println("recipient key missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_RECIPIENT_KEY)
		return
	}

	if !bytes.Equal(recipientKey, srv.config.serverKeys.public[:]) {
		log.Println("recipient key invalid")
		reply.SetError(REPLY_UNACCEPTABLE_VALUE, RECORD_RECIPIENT_KEY)
		return
	}

	if senderKey == nil {
		log.Println("sender key missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_KEY)
		return
	}

	if senderHandshakeKey == nil {
		log.Println("sender handshake key missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_HANDSHAKE_KEY)
		return
	}

	peer := srv.GetPeer(msg.Src)
	peer.PublicKey = senderKey
	peer.peerHandshakeKey = senderHandshakeKey
	peer.lastSeen = time.Now()

	if !peer.makeSharedHandshakeKey(srv.config.serverKeys) {
		log.Println("unable to make shared handshake key")
		return nil
	}

	reply.SignKey = peer.sharedKey
	reply.Records[RECORD_REPLY_CODE] = []byte{REPLY_SUCCESS}
	reply.Records[RECORD_METHOD_LIST] = []byte("null")
	reply.Records[RECORD_VERSION_NAME] = []byte("v18")
	reply.Records[RECORD_MTU] = records[RECORD_MTU]
	reply.Records[RECORD_SENDER_KEY] = srv.config.serverKeys.public[:]
	reply.Records[RECORD_SENDER_HANDSHAKE_KEY] = peer.ourHandshakeKey.public[:]
	reply.Records[RECORD_RECIPIENT_KEY] = senderKey
	reply.Records[RECORD_RECIPIENT_HANDSHAKE_KEY] = senderHandshakeKey

	val := msg.Records[RECORD_HANDSHAKE_TYPE]
	if len(val) != 1 {
		return
	}

	t := val[0]
	switch t {
	case 1:
		if !srv.verifyPeer(peer) {
			return nil
		}
	case 3:
		msg.SignKey = peer.sharedKey
		if !srv.handleFinishHandshake(msg, reply, peer) {
			return nil
		}
	default:
		log.Printf("unsupported handshake type: %d", t)
	}

	return
}

func (srv *Server) handleFinishHandshake(msg *Message, reply *Message, peer *Peer) bool {
	methodName := msg.Records[RECORD_METHOD_NAME]

	if methodName == nil {
		log.Println("method name missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_METHOD_NAME)
		return true
	}
	if string(methodName) != "null" {
		log.Println("method name invalid:", methodName)
		reply.SetError(REPLY_UNACCEPTABLE_VALUE, RECORD_METHOD_NAME)
		return true
	}

	if !msg.VerifySignature() {
		log.Println("invalid signature")
		return false
	}

	if !srv.establishPeer(peer) {
		return false
	}

	// Clear handshake keys
	peer.sharedKey = nil
	peer.peerHandshakeKey = nil

	peer.Ifname = CloneIface("fastd")

	SetRemote(peer.Ifname, peer.Remote, peer.PublicKey)
	peer.SetAddresses(net.ParseIP("192.168.8.0"), net.ParseIP("192.168.8.1"))
	peer.SetAddresses(net.ParseIP("fe80::1"), net.ParseIP("fe80::2"))

	return false
}
