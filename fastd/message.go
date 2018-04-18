package fastd

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/pkg/errors"
)


const (
)

// Known reply codes.
const (
	ReplySuccess byte = iota
	ReplyRecordMissing
	ReplyUnacceptableValue
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
	reply.Records[RecordHandshakeType] = []byte{msg.Records[RecordHandshakeType][0] + 1}
	reply.Records[RecordMode] = msg.Records[RecordMode]
	reply.Records[RecordProtocolName] = msg.Records[RecordProtocolName]
	return reply
}

// SetError sets the error fields
func (msg *Message) SetError(replyCode byte, errorDetail TLVKey) {
	msg.Records[RecordReplyCode] = []byte{replyCode}

	value := make([]byte, 2)
	binary.LittleEndian.PutUint16(value, uint16(errorDetail))
	msg.Records[RecordErrorDetail] = value
}

// VerifySignature calculates the HMAC and verifies it
func (msg *Message) VerifySignature() bool {
	if msg.SignKey == nil {
		return false
	}

	mac := hmac.New(sha256.New, msg.SignKey)
	mac.Write(msg.raw[4:])

	return bytes.Equal(mac.Sum(nil), msg.Records[RecordTLVMAC])
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

// MarshalPayload writes the payload into the given slice. The slice needs
// to be large enough to hold the payload data, or else it will panic.
func (msg *Message) MarshalPayload(out []byte) int {
	// Header
	out[0] = msg.Type
	i := 4

	// Function for appending records
	addRecord := func(key TLVKey, val []byte) {
		binary.LittleEndian.PutUint16(out[i:], uint16(key))
		binary.LittleEndian.PutUint16(out[i+2:], uint16(len(val)))
		copy(out[i+4:], val)
		i += 4 + len(val)
	}

	// Append records
	for key, val := range msg.Records {
		if val != nil {
			addRecord(TLVKey(key), val)
		}
	}

	// Add HMAC (optional)
	if msg.SignKey != nil {
		addRecord(RecordTLVMAC, make([]byte, sha256.Size))
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
		typ := TLVKey(binary.LittleEndian.Uint16(data[0:2]))
		length = binary.LittleEndian.Uint16(data[2:4])

		if typ >= RecordMax {
			// unsupported field
			continue
		}

		// Shift Type+Length
		data = data[4:]
		if uint16(len(data)) < length {
			err = fmt.Errorf("wrong value size: expected=%d actual=%d", length, len(data))
			return
		}

		if typ == RecordTLVMAC {
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
