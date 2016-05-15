package main

import (
	"C"
	"encoding/binary"
	"fmt"
	"net"
)

type Record struct {
	Type  byte
	Value interface{}
}

type Packet struct {
	Type    byte
	Records map[uint16][]byte
}

type Sockaddr struct {
	IP   net.IP
	Port uint16
}

type Message struct {
	Src    *Sockaddr
	Dest   *Sockaddr
	Packet Packet
}

func parseMessage(buf []byte) (msg *Message, err error) {
	// check size
	if len(buf) < 40 {
		err = fmt.Errorf("packet too small (%d bytes)", len(buf))
		return
	}

	msg = &Message{
		Src:  parseSockaddr(buf[0:18]),
		Dest: parseSockaddr(buf[18:36]),
	}
	data := buf[36:]

	// fastd header
	msg.Packet.Type = data[0]
	msg.Packet.Records = make(map[uint16][]byte)
	length := binary.BigEndian.Uint16(data[2:4])

	if len(data)-4 != int(length) {
		err = fmt.Errorf("wrong data size: expected=%d actual=%d", len(data)-4, length)
		return
	}

	// StripShift header
	data = data[4:]

	for len(data) >= 4 {
		typ := binary.LittleEndian.Uint16(data[0:2])
		length = binary.LittleEndian.Uint16(data[2:4])

		// Shift Type+Length
		data = data[4:]
		if uint16(len(data)) < length {
			err = fmt.Errorf("wrong value size: expected=%d actual=%d", length, len(data))
			return
		}

		// Add record
		msg.Packet.Records[typ] = data[:length]

		// Strip data
		data = data[length:]
	}

	return
}

func (msg *Message) Marshal() []byte {
	bytes := make([]byte, 1500)
	i := 0

	copy(bytes[i:], msg.Src.Raw())
	i += 18

	copy(bytes[i:], msg.Dest.Raw())
	i += 18

	bytes[i] = msg.Packet.Type
	i += 4

	// marshal records
	for key, value := range msg.Packet.Records {
		binary.LittleEndian.PutUint16(bytes[i:], key)
		binary.LittleEndian.PutUint16(bytes[i+2:], uint16(len(value)))
		copy(bytes[i+4:], value)
		i += 4 + len(value)
	}

	// Set length
	binary.BigEndian.PutUint16(bytes[38:], uint16(i-40))

	return bytes[:i]
}
