package fastd

import (
	"fmt"
	"log"
	"net"
	"sync"
)

// UDPServer is a userspace stub of the fastd server
type UDPServer struct {
	connections []UDPConn
	recv        chan *Message // Received messages
	wg          sync.WaitGroup
}

// UDPConn holds an active client connection
type UDPConn struct {
	addr Sockaddr
	conn *net.UDPConn
}

// NewUDPServer creates a new UDP based server
func NewUDPServer(addresses []Sockaddr) (ServerImpl, error) {
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

// Close closes all client connections.
func (srv *UDPServer) Close() {
	for _, udpconn := range srv.connections {
		udpconn.conn.Close()
	}
	close(srv.recv)
}

// Peers returns a list of connected peers. This is stubbed and will
// always return an empty list.
func (srv *UDPServer) Peers() []*Peer {
	return nil
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
		srv.read(data, udpconn.addr, src)
	}

	srv.wg.Done()
}

func (srv *UDPServer) read(buf []byte, dst Sockaddr, src *net.UDPAddr) error {
	// check size
	if len(buf) < 4 {
		return fmt.Errorf("packet too small (%d bytes)", len(buf))
	}

	msg, err := ParseMessage(buf, false)
	if err != nil {
		return err
	}

	msg.Dst = dst
	msg.Src = Sockaddr{
		IP:   src.IP,
		Port: uint16(src.Port),
	}
	srv.recv <- msg
	return nil
}

// Find the corresponding
func (srv *UDPServer) findConn(addr Sockaddr) *net.UDPConn {
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
