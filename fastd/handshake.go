package fastd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"reflect"
	"time"

	"github.com/digineo/fastd/ifconfig"
)

type handshake struct {
	sharedKey        []byte
	peerHandshakeKey []byte   // public handshake key from Alice
	ourHandshakeKey  *KeyPair // our handshake key
	timeout          time.Time
}

func NewHandshake(serverKey, ourHandshakeKey *KeyPair, peerPublicKey, peerHandshakeKey []byte) *handshake {
	hs := handshake{
		peerHandshakeKey: peerHandshakeKey,
		ourHandshakeKey:  ourHandshakeKey,
	}

	if !hs.makeSharedKey(serverKey, peerPublicKey) {
		return nil
	}

	return &hs
}

func (hs *handshake) SharedKey() []byte {
	return hs.sharedKey
}

func (srv *Server) handlePacket(msg *Message) (reply *Message) {
	records := msg.Records
	var handshakeType byte

	if val := records[RECORD_HANDSHAKE_TYPE]; len(val) != 1 {
		log.Printf("%v handshake type missing", msg.Src)
		return
	} else {
		handshakeType = val[0]
	}

	senderKey := records[RECORD_SENDER_KEY]
	recipientKey := records[RECORD_RECIPIENT_KEY]
	senderHandshakeKey := records[RECORD_SENDER_HANDSHAKE_KEY]

	log.Printf("%v received handshake type=%x version=%s hostname=%s pubkey=%s", msg.Src, handshakeType, records[RECORD_VERSION_NAME], records[RECORD_HOSTNAME], hex.EncodeToString(senderKey))

	if reflect.DeepEqual(msg.Src, msg.Dst) {
		log.Printf("%v source address equals destination address", msg.Src)
		return
	}

	reply = msg.NewReply()

	if recipientKey == nil {
		log.Printf("%v recipient key missing", msg.Src)
		reply.SetError(REPLY_RECORD_MISSING, RECORD_RECIPIENT_KEY)
		return
	}

	if !bytes.Equal(recipientKey, srv.config.serverKeys.public[:]) {
		log.Printf("%v recipient key invalid: %s", msg.Src, hex.EncodeToString(recipientKey))
		reply.SetError(REPLY_UNACCEPTABLE_VALUE, RECORD_RECIPIENT_KEY)
		return
	}

	if senderKey == nil {
		log.Printf("%v sender key missing", msg.Src)
		reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_KEY)
		return
	}

	if senderHandshakeKey == nil {
		log.Printf("%v sender handshake key missing", msg.Src)
		reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_HANDSHAKE_KEY)
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
	if handshakeType == 1 {
		hs = NewHandshake(srv.config.serverKeys, RandomKeypair(), senderKey, senderHandshakeKey)
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
	reply.Records[RECORD_REPLY_CODE] = []byte{REPLY_SUCCESS}
	reply.Records[RECORD_METHOD_LIST] = []byte("null")
	reply.Records[RECORD_VERSION_NAME] = []byte("v18")
	reply.Records[RECORD_MTU] = records[RECORD_MTU]
	reply.Records[RECORD_SENDER_KEY] = srv.config.serverKeys.public[:]
	reply.Records[RECORD_SENDER_HANDSHAKE_KEY] = hs.ourHandshakeKey.public[:]
	reply.Records[RECORD_RECIPIENT_KEY] = senderKey
	reply.Records[RECORD_RECIPIENT_HANDSHAKE_KEY] = senderHandshakeKey

	switch handshakeType {
	case 1:
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
	methodName := msg.Records[RECORD_METHOD_NAME]
	var mtu uint16

	if methodName == nil {
		reply.SetError(REPLY_RECORD_MISSING, RECORD_METHOD_NAME)
		return fmt.Errorf("method name missing")
	}
	if string(methodName) != "null" {
		reply.SetError(REPLY_UNACCEPTABLE_VALUE, RECORD_METHOD_NAME)
		return fmt.Errorf("method name invalid: %s", methodName)
	}

	if !msg.VerifySignature() {
		return fmt.Errorf("invalid signature")
	}

	if !srv.establishPeer(peer) {
		return fmt.Errorf("handshake timed out")
	}

	// Decode and set MTU
	if val := msg.Records[RECORD_MTU]; len(val) == 0 {
		return fmt.Errorf("%v MTU missing", msg.Src)
	} else if len(val) != 2 {
		return fmt.Errorf("%v MTU invalid: %v", msg.Src, val)
	} else {
		mtu = binary.LittleEndian.Uint16(val)
		if mtu < 576 {
			return fmt.Errorf("%v MTU invalid: %d", msg.Src, mtu)
		}

		if err := ifconfig.SetMTU(peer.Ifname, mtu); err != nil {
			log.Printf("%v unable to set MTU to %d: %s", msg.Src, mtu, err)
		} else {
			peer.MTU = mtu
		}
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
