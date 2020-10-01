package fastd

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"time"

	"github.com/digineo/fastd/ifconfig"
	"github.com/sirupsen/logrus"
)

// MinMTU is the minimal usable MTU, all clients are required to
// support a tunnel MTU of this size.
const MinMTU = 576

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
	res := make([]byte, len(hs.sharedKey))
	copy(res, hs.sharedKey)
	return res
}

func (srv *Server) handlePacket(msg *Message) (reply *Message) {
	llog := log.WithField("src", msg.Src.String())

	records := msg.Records
	handshakeType, err := records.HandshakeType()
	if err != nil {
		llog.WithError(err).Error("handshake type missing")
		return
	}

	senderKey, err := records.SenderKey()
	if err != nil {
		llog.WithError(err).Error("sender key missing")
		return
	}
	recipientKey, err := records.RecipientKey()
	if err != nil {
		llog.WithError(err).Error("recipient key missing")
		return
	}
	senderHandshakeKey, err := records.SenderHandshakeKey()
	if err != nil {
		llog.WithError(err).Error("sender handshake type missing")
		return
	}

	llog = llog.WithFields(logrus.Fields{
		"type":     fmt.Sprintf("0x%02x", handshakeType),
		"version":  string(records[RecordVersionName]),
		"hostname": string(records[RecordHostname]),
		"pubkey":   fmt.Sprintf("%x", senderKey),
	})
	llog.Info("received handshake")

	if reflect.DeepEqual(msg.Src, msg.Dst) {
		llog.WithField("dst", msg.Dst.String()).
			Error("source address equals destination address")
		return
	}

	reply = msg.NewReply()

	if recipientKey == nil {
		llog.Error("recipient key missing")
		reply.SetError(ReplyRecordMissing, RecordRecipientKey)
		return
	}

	if !bytes.Equal(recipientKey, srv.config.serverKeys.public[:]) {
		llog.WithField("rcptkey", fmt.Sprintf("%x", recipientKey)).
			Error("recipient key invalid")
		reply.SetError(ReplyUnacceptableValue, RecordRecipientKey)
		return
	}

	if senderKey == nil {
		llog.Error("sender key missing")
		reply.SetError(ReplyRecordMissing, RecordSenderKey)
		return
	}

	if senderHandshakeKey == nil {
		llog.Error("sender handshake key missing")
		reply.SetError(ReplyRecordMissing, RecordSenderHandshakeKey)
		return
	}

	peer, created := srv.getPeer(msg.Src)
	if peer.PublicKey == nil {
		peer.PublicKey = senderKey
	} else if !bytes.Equal(peer.PublicKey, senderKey) {
		llog.WithFields(logrus.Fields{
			"old": fmt.Sprintf("%x", peer.PublicKey),
			"new": fmt.Sprintf("%x", senderKey),
		}).Error("peer changed public key")
		return nil
	}

	hs := peer.handshake

	// start new handshake?
	if handshakeType == HandshakeRequest {
		hs = NewRespondingHandshake(srv.config.serverKeys, senderKey, senderHandshakeKey)
		if hs == nil {
			llog.WithError(err).
				Error("unable to make shared handshake key")
			return nil
		}
		peer.handshake = hs
	} else if hs == nil {
		log.Error("no handshake started")
		return nil
	}

	peer.lastSeen = time.Now()

	reply.SignKey = hs.sharedKey
	reply.Records.
		SetReplyCode(ReplySuccess).
		SetMethodList("null").
		SetVersionName("v20").
		SetSenderKey(srv.config.serverKeys.public[:]).
		SetSenderHandshakeKey(hs.ourHandshakeKey.public[:]).
		SetRecipientKey(senderKey).
		SetRecipientHandshakeKey(senderHandshakeKey)

	// avoid casting from byte → uint16 → byte
	reply.Records[RecordMTU] = records[RecordMTU]

	switch handshakeType {
	case HandshakeRequest:
		if err := srv.verifyPeer(peer); err != nil {
			llog.WithError(err).
				Error("verify failed")
			if created {
				srv.RemovePeer(peer)
			}
			return nil
		}

		var useCompactHeader bool
		if records[RecordVersionName] != nil && len(records[RecordVersionName]) > 1 {
			val, err := strconv.Atoi(string(records[RecordVersionName])[1:])

			useCompactHeader = err == nil && val >= 20
		}

		// Assign interface and addresses
		var err error
		if peer.Ifname == "" {
			peer.Ifname, err = Clone(msg.Src, senderKey, useCompactHeader)

			if err != nil {
				llog.WithError(err).Error("cloning failed")
				if created {
					srv.RemovePeer(peer)
				}
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
		// don't reply to the finish message
		reply = nil

		msg.SignKey = hs.sharedKey
		if err := srv.handleFinishHandshake(msg, reply, peer); err != nil {
			llog.WithError(err).Error("handshake failed")
			return nil
		}
	default:
		llog.Error("unsupported handshake type")
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
	if mtu < MinMTU {
		return fmt.Errorf("%v MTU invalid: %d", msg.Src, mtu)
	}
	if err := ifconfig.SetMTU(peer.Ifname, mtu); err != nil {
		log.WithFields(logrus.Fields{
			logrus.ErrorKey: err,
			"src":           msg.Src.String(),
			"mtu":           mtu,
		}).Error("unable to set MTU")
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
