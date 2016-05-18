package main

import (
	"log"
)

func handlePacket(msg *Message) (reply *Message) {
	records := msg.Records
	val := records[RECORD_HANDSHAKE_TYPE]
	if len(val) != 1 {
		return
	}

	t := val[0]

	switch t {
	case 1:
		// Handshake request
		reply = msg.NewReply()
		for k, v := range records {
			log.Println(k, v)
		}

		senderKey := records[RECORD_SENDER_KEY]
		recipientKey := records[RECORD_RECIPIENT_KEY]
		senderHandshakeKey := records[RECORD_SENDER_HANDSHAKE_KEY]

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
		if senderHandshakeKey == nil {
			log.Println("sender handshake key missing")
			reply.SetError(REPLY_RECORD_MISSING, RECORD_SENDER_HANDSHAKE_KEY)
			return
		}

		log.Printf("received handshake from %s[%d] using fastd %s", msg.Src.IP.String(), msg.Src.Port, records[RECORD_VERSION_NAME])

		// TODO check recipientKey
		// TODO check timeout
		reply.Records[RECORD_REPLY_CODE] = []byte{REPLY_SUCCESS}
		reply.Records[RECORD_METHOD_LIST] = []byte("null")
		reply.Records[RECORD_VERSION_NAME] = []byte("v18")
		reply.Records[RECORD_MTU] = records[RECORD_MTU]
		reply.Records[RECORD_SENDER_KEY] = recipientKey
		reply.Records[RECORD_RECIPIENT_KEY] = senderKey
		reply.Records[RECORD_RECIPIENT_HANDSHAKE_KEY] = senderHandshakeKey
	case 3:
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

		// TODO

	default:
		log.Printf("unsupported handshake type: %d", t)
	}

	return
}
