package main

import (
	"fmt"
	"log"
	"net"
)

func udpTest(msg string) {
	addr := &net.UDPAddr{
		IP:   listenAddr,
		Port: int(listenPort),
	}

	log.Println("send packet")

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
