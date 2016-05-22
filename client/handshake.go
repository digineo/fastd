package main

import (
	"bytes"
	"log"
)

func handlePacket(msg *Message) (reply *Message) {
	val := msg.Records[RECORD_HANDSHAKE_TYPE]
	if len(val) != 1 {
		return
	}

	t := val[0]
	switch t {
	case 1:
		reply = respondHandshake(msg)
	case 3:
		reply = handleFinishHandshake(msg)
	default:
		log.Printf("unsupported handshake type: %d", t)
	}

	return
}

// Handshake request
func respondHandshake(msg *Message) (reply *Message) {
	records := msg.Records
	reply = msg.NewReply()

	senderKey := records[RECORD_SENDER_KEY]
	recipientKey := records[RECORD_RECIPIENT_KEY]
	senderHandshakeKey := records[RECORD_SENDER_HANDSHAKE_KEY]

	log.Printf("received handshake from %s[%d] using fastd %s", msg.Src.IP.String(), msg.Src.Port, records[RECORD_VERSION_NAME])

	if senderKey == nil {
		log.Println("sender key missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_KEY)
		return
	}
	if recipientKey == nil {
		log.Println("recipient key missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_RECIPIENT_KEY)
		return
	}
	if !bytes.Equal(recipientKey, config.serverKeys.public[:]) {
		log.Println("recipient key invalid")
		reply.SetError(REPLY_UNACCEPTABLE_VALUE, RECORD_RECIPIENT_KEY)
		return
	}
	if senderHandshakeKey == nil {
		log.Println("sender handshake key missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_HANDSHAKE_KEY)
		return
	}

	handshakeKey := RandomKeypair()

	peer := &Peer{
		publicKey:        senderKey,
		peerHandshakeKey: senderHandshakeKey,
		ourHandshakeKey:  &handshakeKey,
	}

	if !peer.makeSharedHandshakeKey() {
		log.Println("unable to make shared handshake key")
		return nil
	}

	// TODO check timeout
	reply.SignKey = peer.sharedKey
	reply.Records[RECORD_REPLY_CODE] = []byte{REPLY_SUCCESS}
	reply.Records[RECORD_METHOD_LIST] = []byte("null")
	reply.Records[RECORD_VERSION_NAME] = []byte("v18")
	reply.Records[RECORD_MTU] = records[RECORD_MTU]
	reply.Records[RECORD_SENDER_KEY] = recipientKey
	reply.Records[RECORD_SENDER_HANDSHAKE_KEY] = peer.ourHandshakeKey.public[:]
	reply.Records[RECORD_RECIPIENT_KEY] = senderKey
	reply.Records[RECORD_RECIPIENT_HANDSHAKE_KEY] = senderHandshakeKey

	return reply
}

func handleFinishHandshake(msg *Message) (reply *Message) {
	reply = msg.NewReply()

	// Handshake finish
	methodName := msg.Records[RECORD_METHOD_NAME]
	if methodName == nil {
		log.Println("method name missing")
		reply.SetError(REPLY_RECORD_MISSING, RECORD_METHOD_NAME)
		return
	}
	if string(methodName) != "null" {
		log.Println("method name invalid:", methodName)
		reply.SetError(REPLY_UNACCEPTABLE_VALUE, RECORD_METHOD_NAME)
		return
	}

	reply.Records[RECORD_REPLY_CODE] = []byte{REPLY_SUCCESS}
	return reply
}
