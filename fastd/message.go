package fastd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
)

type TLV_KEY uint16

func (key TLV_KEY) String() string {
	switch key {
	case RECORD_HANDSHAKE_TYPE:
		return "handshake_type"
	case RECORD_REPLY_CODE:
		return "reply_code"
	case RECORD_ERROR_DETAIL:
		return "error_detail"
	case RECORD_FLAGS:
		return "flags"
	case RECORD_MODE:
		return "mode"
	case RECORD_PROTOCOL_NAME:
		return "protocol_name"
	case RECORD_SENDER_KEY:
		return "sender_key"
	case RECORD_RECIPIENT_KEY:
		return "recipient_key"
	case RECORD_SENDER_HANDSHAKE_KEY:
		return "sender_handshake_key"
	case RECORD_RECIPIENT_HANDSHAKE_KEY:
		return "recipient_handshake_key"
	case RECORD_AUTHENTICATION_TAG:
		return "authentication_tag"
	case RECORD_MTU:
		return "mtu"
	case RECORD_METHOD_NAME:
		return "method_name"
	case RECORD_VERSION_NAME:
		return "version_name"
	case RECORD_METHOD_LIST:
		return "method_list"
	case RECORD_TLV_MAC:
		return "tlv_mac"
	case RECORD_IPV4_ADDR:
		return "ipv4_addr"
	case RECORD_IPV4_DSTADDR:
		return "ipv4_dstaddr"
	case RECORD_IPV4_PREFIXLEN:
		return "ipv4_prefixlen"
	case RECORD_IPV6_ADDR:
		return "ipv6_addr"
	case RECORD_IPV6_DSTADDR:
		return "ipv6_dstaddr"
	case RECORD_IPV6_PREFIXLEN:
		return "ipv6_prefixlen"
	case RECORD_VARS:
		return "vars"
	case RECORD_HOSTNAME:
		return "hostname"
	}
	return fmt.Sprintf("%%!(TLV_KEY value=%02x)", uint16(key))
}

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

	// Inofficial yet
	RECORD_IPV4_ADDR
	RECORD_IPV4_DSTADDR
	RECORD_IPV4_PREFIXLEN
	RECORD_IPV6_ADDR
	RECORD_IPV6_DSTADDR
	RECORD_IPV6_PREFIXLEN
	RECORD_VARS
	RECORD_HOSTNAME

	RECORD_MAX
)

const (
	REPLY_SUCCESS byte = iota
	REPLY_RECORD_MISSING
	REPLY_UNACCEPTABLE_VALUE
)

// Message is a fastd handshake message
type Message struct {
	Src     Sockaddr
	Dst     Sockaddr
	Type    byte
	Records Records
	SignKey []byte
	raw     []byte
}

// NewReply creates a reply to the message
func (msg *Message) NewReply() *Message {
	reply := &Message{
		Type: 0x01,
		Src:  msg.Dst,
		Dst:  msg.Src,
	}
	reply.Records[RECORD_HANDSHAKE_TYPE] = []byte{msg.Records[RECORD_HANDSHAKE_TYPE][0] + 1}
	reply.Records[RECORD_MODE] = msg.Records[RECORD_MODE]
	reply.Records[RECORD_PROTOCOL_NAME] = msg.Records[RECORD_PROTOCOL_NAME]
	return reply
}

// SetError sets the error fields
func (msg *Message) SetError(replyCode byte, errorDetail TLV_KEY) {
	msg.Records[RECORD_REPLY_CODE] = []byte{replyCode}

	value := make([]byte, 2)
	binary.LittleEndian.PutUint16(value, uint16(errorDetail))
	msg.Records[RECORD_ERROR_DETAIL] = value
}

// VerifySignature calculates the HMAC and verifies it
func (msg *Message) VerifySignature() bool {
	if msg.SignKey == nil {
		return false
	}

	mac := hmac.New(sha256.New, msg.SignKey)
	mac.Write(msg.raw[4:])

	return bytes.Equal(mac.Sum(nil), msg.Records[RECORD_TLV_MAC])
}

// ParseMessage parses the message bytes
func ParseMessage(buf []byte, includeSockaddr bool) (*Message, error) {
	msg := &Message{}
	offset := 0
	if includeSockaddr {
		if len(buf) < 40 {
			return nil, fmt.Errorf("packet too small (%d bytes)", len(buf))
		}
		msg.Src = parseSockaddr(buf[0:18])
		msg.Dst = parseSockaddr(buf[18:36])
		offset = 36
	} else if len(buf) < 4 {
		return nil, fmt.Errorf("packet too small (%d bytes)", len(buf))
	}

	msg.Type = buf[offset]
	msg.raw = buf[offset:]

	if err := msg.Unmarshal(msg.raw); err != nil {
		return nil, errors.Wrap(err, "unmarshal failed")
	}

	return msg, nil
}

// Marshal serializes the message and optionally adds the HMAC
func (msg *Message) Marshal(includeSockaddr bool) []byte {
	bytes := make([]byte, 1500)
	offset := 0

	if includeSockaddr {
		msg.Src.Write(bytes)
		msg.Dst.Write(bytes[18:])
		offset = 36
	}

	n := msg.MarshalPayload(bytes[offset:])
	return bytes[:offset+n]
}

func (msg *Message) MarshalPayload(out []byte) int {
	// Header
	out[0] = msg.Type
	i := 4

	// Function for appending records
	addRecord := func(key TLV_KEY, val []byte) {
		binary.LittleEndian.PutUint16(out[i:], uint16(key))
		binary.LittleEndian.PutUint16(out[i+2:], uint16(len(val)))
		copy(out[i+4:], val)
		i += 4 + len(val)
	}

	// Append records
	for key, val := range msg.Records {
		if val != nil {
			addRecord(TLV_KEY(key), val)
		}
	}

	// Add HMAC (optional)
	if msg.SignKey != nil {
		addRecord(RECORD_TLV_MAC, make([]byte, sha256.Size))
		mac := hmac.New(sha256.New, msg.SignKey)
		mac.Write(out[4:i])
		copy(out[i-sha256.Size:], mac.Sum(nil))
	}

	// Set length
	binary.BigEndian.PutUint16(out[2:], uint16(i-4))

	return i
}

// Unmarshal decodes the packet
// It will zero the HMAC bytes in the given slice
func (msg *Message) Unmarshal(data []byte) (err error) {
	msg.Type = data[0]

	// fastd header
	length := binary.BigEndian.Uint16(data[2:4])

	if len(data)-4 != int(length) {
		err = fmt.Errorf("wrong data size: expected=%d actual=%d", length, len(data))
		return
	}

	// Shift header
	data = data[4:]

	for len(data) >= 4 {
		typ := TLV_KEY(binary.LittleEndian.Uint16(data[0:2]))
		length = binary.LittleEndian.Uint16(data[2:4])

		if typ >= RECORD_MAX {
			// unsupported field
			continue
		}

		// Shift Type+Length
		data = data[4:]
		if uint16(len(data)) < length {
			err = fmt.Errorf("wrong value size: expected=%d actual=%d", length, len(data))
			return
		}

		if typ == RECORD_TLV_MAC {
			// Add record and copy value
			value := make([]byte, length)
			copy(value, data[:length])
			msg.Records[typ] = value

			// Zero the source bytes to conform the HMAC function
			for i := 0; i < int(length); i++ {
				data[i] = 0
			}
		} else {
			// Add record and reference value
			msg.Records[typ] = data[:length]

			/*
				if typ == RECORD_HANDSHAKE_TYPE {
					ioutil.WriteFile(fmt.Sprintf("null-%d.dat", data[0]), msg.raw, 0644)
				}
			*/
		}

		// Strip data
		data = data[length:]
	}

	return
}
