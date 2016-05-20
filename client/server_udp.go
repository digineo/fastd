package main

import (
	"fmt"
	"log"
	"net"
)

type UDPServer struct {
	conn *net.UDPConn
	recv chan *Message // Received messages
}

func NewUDPServer(listenAddr net.IP, listenPort uint16) (Server, error) {

	addr := net.UDPAddr{
		IP:   listenAddr,
		Port: int(listenPort),
	}

	log.Printf("Listening on %s, Port %d", listenAddr.String(), listenPort)

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return nil, err
	}

	srv := &UDPServer{
		recv: make(chan *Message, 10),
		conn: conn,
	}

	go srv.readPackets()

	return srv, nil
}

func (srv *UDPServer) Read() chan *Message {
	return srv.recv
}

func (srv *UDPServer) Close() {
	if srv.conn != nil {
		srv.conn.Close()
	}
	close(srv.recv)
}

func (srv *UDPServer) readPackets() error {
	buf := make([]byte, 1500)

	for {
		n, addr, err := srv.conn.ReadFromUDP(buf)

		if err != nil {
			fmt.Println("Error reading from UDP:", err)
		} else {
			srv.read(buf[:n], addr)
		}
	}
}

func (srv *UDPServer) read(buf []byte, addr *net.UDPAddr) error {
	// check size
	if len(buf) < 4 {
		return fmt.Errorf("packet too small (%d bytes)", len(buf))
	}

	if msg, err := ParseMessage(buf, false); err != nil {
		return err
	} else {
		msg.Src = &Sockaddr{
			IP:   addr.IP,
			Port: uint16(addr.Port),
		}
		srv.recv <- msg
		return nil
	}

}

func (srv *UDPServer) Write(msg *Message) error {
	bytes := msg.Marshal(nil, false)
	addr := net.UDPAddr{
		Port: int(msg.Dst.Port),
		IP:   msg.Dst.IP,
	}
	_, err := srv.conn.WriteToUDP(bytes, &addr)
	return err
}
