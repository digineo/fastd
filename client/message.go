package main

import (
	"C"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

type TLV_KEY uint16

const (
	RECORD_HANDSHAKE_TYPE TLV_KEY = iota
	RECORD_REPLY_CODE
	RECORD_ERROR_DETAIL
	RECORD_FLAGS
	RECORD_MODE
	RECORD_PROTOCOL_NAME
	RECORD_SENDER_KEY
	RECORD_RECIPIENT_KEY
	RECORD_SENDER_HANDSHAKE_KEY
	RECORD_RECIPIENT_HANDSHAKE_KEY
	RECORD_AUTHENTICATION_TAG
	RECORD_MTU
	RECORD_METHOD_NAME
	RECORD_VERSION_NAME
	RECORD_METHOD_LIST
	RECORD_TLV_MAC
)

const (
	REPLY_SUCCESS byte = iota
	REPLY_RECORD_MISSING
	REPLY_UNACCEPTABLE_VALUE
)

type Records map[TLV_KEY][]byte

type Message struct {
	Src     *Sockaddr
	Dst     *Sockaddr
	Type    byte
	Records Records
}

func parseMessage(buf []byte) (msg *Message, err error) {
	// check size
	if len(buf) < 40 {
		err = fmt.Errorf("packet too small (%d bytes)", len(buf))
		return
	}

	msg = NewMessage(buf[37], parseSockaddr(buf[0:18]), parseSockaddr(buf[18:36]))
	data := buf[36:]

	// fastd header
	length := binary.BigEndian.Uint16(data[2:4])

	if len(data)-4 != int(length) {
		err = fmt.Errorf("wrong data size: expected=%d actual=%d", len(data)-4, length)
		return
	}

	// Shift header
	data = data[4:]

	for len(data) >= 4 {
		typ := TLV_KEY(binary.LittleEndian.Uint16(data[0:2]))
		length = binary.LittleEndian.Uint16(data[2:4])

		// Shift Type+Length
		data = data[4:]
		if uint16(len(data)) < length {
			err = fmt.Errorf("wrong value size: expected=%d actual=%d", length, len(data))
			return
		}

		// Add record
		msg.Records[typ] = data[:length]

		// Strip data
		data = data[length:]
	}

	return
}

func NewMessage(typ byte, src *Sockaddr, dst *Sockaddr) *Message {
	return &Message{
		Type:    typ,
		Src:     src,
		Dst:     dst,
		Records: make(Records),
	}
}

// Creates a reply to the message
func (msg *Message) NewReply() *Message {
	reply := NewMessage(msg.Type+1, msg.Dst, msg.Src)
	reply.Records[RECORD_MODE] = msg.Records[RECORD_MODE]
	reply.Records[RECORD_PROTOCOL_NAME] = msg.Records[RECORD_PROTOCOL_NAME]
	return reply
}

// Set error fields
func (msg *Message) SetError(replyCode byte, errorDetail TLV_KEY) {
	msg.Records[RECORD_REPLY_CODE] = []byte{replyCode}

	value := make([]byte, 2)
	binary.LittleEndian.PutUint16(value, uint16(errorDetail))
	msg.Records[RECORD_ERROR_DETAIL] = value
}

// Serialize message and optionally add the HMAC
func (msg *Message) Marshal(key []byte) []byte {
	bytes := make([]byte, 1500)
	i := 0

	// Source address
	copy(bytes[i:], msg.Src.Raw())
	i += 18

	// Destination address
	copy(bytes[i:], msg.Dst.Raw())
	i += 18

	// Header
	bytes[i] = msg.Type
	i += 4

	addRecord := func(key TLV_KEY, val []byte) {
		binary.LittleEndian.PutUint16(bytes[i:], uint16(key))
		binary.LittleEndian.PutUint16(bytes[i+2:], uint16(len(val)))
		copy(bytes[i+4:], val)
		i += 4 + len(val)
	}

	// Append records
	for key, val := range msg.Records {
		addRecord(key, val)
	}

	// Add HMAC (optional)
	if key != nil {
		mac := hmac.New(sha256.New, key)
		mac.Write(bytes[40:i])
		addRecord(RECORD_TLV_MAC, mac.Sum(nil))
	}

	// Set length
	binary.BigEndian.PutUint16(bytes[38:], uint16(i-40))

	return bytes[:i]
}

// String representation of the records
func (records Records) String() string {
	var buffer bytes.Buffer

	buffer.WriteString("Records[ ")
	for key, val := range records {
		buffer.WriteString(fmt.Sprintf("%#04x=%x ", key, val))
	}
	buffer.WriteString("]")

	return buffer.String()
}
