package main

import (
	"fmt"
	"net"
)

func udpTest(msg string) {
	addr := &net.UDPAddr{
		IP:   listenAddr,
		Port: int(listenPort),
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	buf := []byte(msg)
	_, err = conn.Write(buf)
	if err != nil {
		fmt.Println(msg, err)
	}

}
