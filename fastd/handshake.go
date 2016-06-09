package fastd

import (
	"bytes"
	"encoding/hex"
	"github.com/digineo/fastd/ifconfig"
	"log"
	"reflect"
	"time"
)

func (srv *Server) handlePacket(msg *Message) (reply *Message) {
	records := msg.Records
	var handshakeType byte

	if val := records[RECORD_HANDSHAKE_TYPE]; len(val) != 1 {
		log.Println("handshake type missing")
		return
	} else {
		handshakeType = val[0]
	}

	log.Printf("received handshake %x from %s[%d] using fastd version=%s hostname=%s", handshakeType, msg.Src.IP.String(), msg.Src.Port, records[RECORD_VERSION_NAME], records[RECORD_HOSTNAME])

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
		log.Println("recipient key invalid:", hex.EncodeToString(recipientKey))
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

	switch handshakeType {
	case 1:
		if !srv.verifyPeer(peer) {
			return nil
		}

		// Assign interface and addresses
		peer.Ifname = ifconfig.Clone("fastd")
		if f := srv.config.AssignAddresses; f != nil {
			f(peer)
		}

		// Copy Vars
		if peer.Vars != nil {
			reply.Records[RECORD_VARS] = peer.Vars
		}

		// Copy IPv4 addresses into response
		if peer.IPv4.LocalAddr != nil && peer.IPv4.DestAddr != nil {
			reply.Records[RECORD_IPV4_ADDR] = []byte(peer.IPv4.DestAddr.To4())
			reply.Records[RECORD_IPV4_DSTADDR] = []byte(peer.IPv4.LocalAddr.To4())
		}

		// Copy IPv6 addresses into response
		if peer.IPv6.LocalAddr != nil && peer.IPv6.DestAddr != nil {
			reply.Records[RECORD_IPV6_ADDR] = []byte(peer.IPv6.DestAddr.To16())
			reply.Records[RECORD_IPV6_DSTADDR] = []byte(peer.IPv6.LocalAddr.To16())
		}
	case 3:
		msg.SignKey = peer.sharedKey
		if !srv.handleFinishHandshake(msg, reply, peer) {
			return nil
		}
	default:
		log.Printf("unsupported handshake type: %d", handshakeType)
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

	if err := SetRemote(peer.Ifname, peer.Remote, peer.PublicKey); err != nil {
		log.Printf("unable to set remote for %s: %s", peer.Ifname, err)
	}

	peer.SetAddresses(peer.IPv4)
	peer.SetAddresses(peer.IPv6)

	return false
}
