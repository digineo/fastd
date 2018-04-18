package fastd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/digineo/fastd/ifconfig"
)

// Handshake is used between two peers to exchange a secret.
type Handshake struct {
	sharedKey        []byte
	peerHandshakeKey []byte   // public handshake key from Alice
	ourHandshakeKey  *KeyPair // our handshake key
	timeout          time.Time
}

// NewInitiatingHandshake initiates a new handshake.
func NewInitiatingHandshake(ourKey, ourHandshakeKey *KeyPair, peerPublicKey, peerHandshakeKey []byte) *Handshake {
	return newHandshake(true, ourKey, ourHandshakeKey, peerPublicKey, peerHandshakeKey)
}

// NewRespondingHandshake responds to a handshake.
func NewRespondingHandshake(ourKey *KeyPair, peerPublicKey, peerHandshakeKey []byte) *Handshake {
	return newHandshake(false, ourKey, RandomKeypair(), peerPublicKey, peerHandshakeKey)
}

func newHandshake(initiator bool, ourKey, ourHandshakeKey *KeyPair, peerPublicKey, peerHandshakeKey []byte) *Handshake {
	hs := Handshake{
		peerHandshakeKey: peerHandshakeKey,
		ourHandshakeKey:  ourHandshakeKey,
	}

	if !hs.makeSharedKey(initiator, ourKey, peerPublicKey) {
		return nil
	}

	return &hs
}

// SharedKey returns a copy of the shared key.
func (hs *Handshake) SharedKey() []byte {
	res := make([]byte, len(hs.sharedKey), len(hs.sharedKey))
	copy(res, hs.sharedKey)
	return res
}

func (srv *Server) handlePacket(msg *Message) (reply *Message) {
	records := msg.Records
	handshakeType, err := records.HandshakeType()
	if err != nil {
		log.Printf("%v handshake type missing", msg.Src)
		return
	}

	senderKey, err := records.SenderKey()
	if err != nil {
		log.Printf("%v sender key missing", msg.Src)
		return
	}
	recipientKey, err := records.RecipientKey()
	if err != nil {
		log.Printf("%v recipient key missing", msg.Src)
		return
	}
	senderHandshakeKey, err := records.SenderHandshakeKey()
	if err != nil {
		log.Printf("%v sender handshake type missing", msg.Src)
		return
	}

	log.Printf("%v received handshake type=%x version=%s hostname=%s pubkey=%s",
		msg.Src, handshakeType, records[RecordVersionName], records[RecordHostname], hex.EncodeToString(senderKey))

	if reflect.DeepEqual(msg.Src, msg.Dst) {
		log.Printf("%v source address equals destination address", msg.Src)
		return
	}

	reply = msg.NewReply()

	if recipientKey == nil {
		log.Printf("%v recipient key missing", msg.Src)
		reply.SetError(ReplyRecordMissing, RecordRecipientKey)
		return
	}

	if !bytes.Equal(recipientKey, srv.config.serverKeys.public[:]) {
		log.Printf("%v recipient key invalid: %s", msg.Src, hex.EncodeToString(recipientKey))
		reply.SetError(ReplyUnacceptableValue, RecordRecipientKey)
		return
	}

	if senderKey == nil {
		log.Printf("%v sender key missing", msg.Src)
		reply.SetError(ReplyRecordMissing, RecordSenderKey)
		return
	}

	if senderHandshakeKey == nil {
		log.Printf("%v sender handshake key missing", msg.Src)
		reply.SetError(ReplyRecordMissing, RecordSenderHandshakeKey)
		return
	}

	peer := srv.GetPeer(msg.Src)

	if peer.PublicKey == nil {
		peer.PublicKey = senderKey
	} else if !bytes.Equal(peer.PublicKey, senderKey) {
		log.Printf("%v peer changed public key old=%s new=%s", msg.Src, hex.EncodeToString(peer.PublicKey), hex.EncodeToString(senderKey))
		return nil
	}

	hs := peer.handshake

	// start new handshake?
	if handshakeType == HandshakeRequest {
		hs = NewRespondingHandshake(srv.config.serverKeys, senderKey, senderHandshakeKey)
		if hs == nil {
			log.Printf("%v unable to make shared handshake key", msg.Src)
			return nil
		}
		peer.handshake = hs
	} else if hs == nil {
		log.Printf("%v no handshake started", msg.Src)
		return nil
	}

	peer.lastSeen = time.Now()

	reply.SignKey = hs.sharedKey
	reply.Records.
		SetReplyCode(ReplySuccess).
		SetMethodList("null").
		SetVersionName("v18").
		SetSenderKey(srv.config.serverKeys.public[:]).
		SetSenderHandshakeKey(hs.ourHandshakeKey.public[:]).
		SetRecipientKey(senderKey).
		SetRecipientHandshakeKey(senderHandshakeKey)

	// avoid casting from byte → uint16 → byte
	reply.Records[RecordMTU] = records[RecordMTU]

	switch handshakeType {
	case HandshakeRequest:
		if err := srv.verifyPeer(peer); err != nil {
			log.Printf("%v verify failed: %s", msg.Src, err)
			return nil
		}

		// Assign interface and addresses
		var err error
		if peer.Ifname == "" {
			peer.Ifname, err = Clone(msg.Src, senderKey)

			if err != nil {
				log.Printf("%v cloning failed: %s", msg.Src, err)
				return nil
			}
		}

		if f := srv.config.AssignAddresses; f != nil {
			f(peer)
		}

		// Copy Vars
		if peer.Vars != nil {
			reply.Records.SetVars(peer.Vars)
		}

		// Copy IPv4 addresses into response
		if peer.IPv4.LocalAddr != nil && peer.IPv4.DestAddr != nil {
			reply.Records.SetIPv4Addr(peer.IPv4.DestAddr)
			reply.Records.SetIPv4DstAddr(peer.IPv4.LocalAddr)
		}

		// Copy IPv6 addresses into response
		if peer.IPv6.LocalAddr != nil && peer.IPv6.DestAddr != nil {
			reply.Records.SetIPv6Addr(peer.IPv6.DestAddr)
			reply.Records.SetIPv6DstAddr(peer.IPv6.LocalAddr)
		}
	case HandshakeFinish:
		msg.SignKey = hs.sharedKey
		if err := srv.handleFinishHandshake(msg, reply, peer); err != nil {
			log.Printf("%v handshake failed: %s", msg.Src, err)
			return nil
		}
	default:
		log.Printf("%v unsupported handshake type", msg.Src)
	}

	return
}

func (srv *Server) handleFinishHandshake(msg *Message, reply *Message, peer *Peer) error {
	methodName := msg.Records[RecordMethodName]

	if methodName == nil {
		reply.SetError(ReplyRecordMissing, RecordMethodName)
		return fmt.Errorf("method name missing")
	}
	if string(methodName) != "null" {
		reply.SetError(ReplyUnacceptableValue, RecordMethodName)
		return fmt.Errorf("method name invalid: %s", methodName)
	}

	if !msg.VerifySignature() {
		return fmt.Errorf("invalid signature")
	}

	if !srv.establishPeer(peer) {
		return fmt.Errorf("handshake timed out")
	}

	// Decode and set MTU
	mtu, err := msg.Records.MTU()
	if err != nil {
		return fmt.Errorf("%v %v", msg.Src, err)
	}
	if mtu < 576 {
		return fmt.Errorf("%v MTU invalid: %d", msg.Src, mtu)
	}
	if err := ifconfig.SetMTU(peer.Ifname, mtu); err != nil {
		log.Printf("%v unable to set MTU to %d: %s", msg.Src, mtu, err)
	} else {
		peer.MTU = mtu
	}

	// Clear handshake keys
	peer.handshake = nil

	peer.assignAddresses()

	// Established hook
	if f := srv.config.OnEstablished; f != nil {
		f(peer)
	}

	return nil
}
