package main

import (
	"fmt"
	"log"
	"net"
	"sync"
)

type UDPServer struct {
	connections []UDPConn
	recv        chan *Message // Received messages
	wg          sync.WaitGroup
}

type UDPConn struct {
	addr Sockaddr
	conn *net.UDPConn
}

func NewUDPServer(addresses []Sockaddr) (Server, error) {

	srv := &UDPServer{
		recv: make(chan *Message, 10),
	}

	for _, sa := range addresses {
		addr := net.UDPAddr{
			IP:   sa.IP,
			Port: int(sa.Port),
		}

		log.Printf("Listening on %s, Port %d", addr.IP.String(), addr.Port)

		conn, err := net.ListenUDP("udp", &addr)
		if err != nil {
			srv.Close()
			return nil, err
		}
		udpconn := UDPConn{sa, conn}
		srv.connections = append(srv.connections, udpconn)
		go srv.readPackets(&udpconn)
	}

	return srv, nil
}

func (srv *UDPServer) Read() chan *Message {
	return srv.recv
}

func (srv *UDPServer) Close() {
	for _, udpconn := range srv.connections {
		udpconn.conn.Close()
	}
	close(srv.recv)
}

func (srv *UDPServer) readPackets(udpconn *UDPConn) {
	buf := make([]byte, 1500)

	for {
		n, src, err := udpconn.conn.ReadFromUDP(buf)

		if err != nil {
			fmt.Println("Error reading from UDP:", err)
			break
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		srv.read(data, &udpconn.addr, src)
	}

	srv.wg.Done()
}

func (srv *UDPServer) read(buf []byte, dst *Sockaddr, src *net.UDPAddr) error {
	// check size
	if len(buf) < 4 {
		return fmt.Errorf("packet too small (%d bytes)", len(buf))
	}

	if msg, err := ParseMessage(buf, false); err != nil {
		return err
	} else {
		msg.Dst = dst
		msg.Src = &Sockaddr{
			IP:   src.IP,
			Port: uint16(src.Port),
		}
		srv.recv <- msg
		return nil
	}
}

// Find the corresponding
func (srv *UDPServer) findConn(addr *Sockaddr) *net.UDPConn {
	for _, udpconn := range srv.connections {
		if udpconn.addr.Family() == addr.Family() {
			return udpconn.conn
		}
	}
	return nil
}

func (srv *UDPServer) Write(msg *Message) error {
	conn := srv.findConn(msg.Src)
	if conn == nil {
		log.Println("unable to find connection with local address", msg.Src)
		return fmt.Errorf("no local connection with address %v", msg.Src)
	}

	bytes := msg.Marshal(false)
	addr := net.UDPAddr{
		Port: int(msg.Dst.Port),
		IP:   msg.Dst.IP,
	}
	_, err := conn.WriteToUDP(bytes, &addr)
	return err
}
