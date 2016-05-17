package main

import (
	"errors"
	"log"
)

func handlePacket(msg *Message) (reply *Message, err error) {
	records := msg.Records
	val := records[RECORD_HANDSHAKE_TYPE]
	if len(val) != 1 {
		return
	}

	t := val[0]

	switch t {
	case 1:
		// Handshake request
		reply = msg.NewReply(0x02)
		for k, v := range records {
			log.Println(k, v)
		}

		senderKey := records[RECORD_SENDER_KEY]
		recipientKey := records[RECORD_RECIPIENT_KEY]
		senderHandshakeKey := records[RECORD_SENDER_HANDSHAKE_KEY]
		tlvMac := records[RECORD_TLV_MAC]

		if senderKey == nil {
			errors.New("sender key missing")
			return
		}
		if recipientKey == nil {
			errors.New("recipient key missing")
			return
		}
		if senderHandshakeKey == nil {
			errors.New("sender handshake key missing")
			return
		}
		if tlvMac == nil {
			errors.New("TLV authentication tag missing")
			return
		}

		log.Printf("received handshake from %s[%d] using fastd %s", msg.Src.IP.String(), msg.Src.Port, records[RECORD_VERSION_NAME])

		// TODO check recipientKey
		// TODO check timeout
		reply.Records[RECORD_METHOD_LIST] = []byte("null")
		reply.Records[RECORD_VERSION_NAME] = []byte("v18")
		reply.Records[RECORD_MTU] = records[RECORD_MTU]
		reply.Records[RECORD_SENDER_KEY] = recipientKey
		reply.Records[RECORD_RECIPIENT_KEY] = senderKey
		reply.Records[RECORD_RECIPIENT_HANDSHAKE_KEY] = senderHandshakeKey

	case 3:
	// Handshake finish
	default:
		log.Printf("unsupported handshake type: %d", t)
	}

	return
}
