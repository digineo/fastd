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

type Message struct {
	Address net.IP
	Port    uint16
	Packet  Packet
}

func parseMessage(buf []byte) (msg *Message, err error) {
	// check size
	if len(buf) < SockaddrSize+4 {
		err = fmt.Errorf("packet too small (%d bytes)", len(buf))
		return
	}

	// sockaddr
	addr, port := parseRawSockaddr(buf)
	if port == 0 || addr == nil {
		err = fmt.Errorf("invalid sockaddr")
		return
	}

	// fastd header
	data := buf[SockaddrSize:]
	msg = &Message{
		Port:    port,
		Address: addr,
	}
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
