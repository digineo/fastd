package fastd

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// DevicePath is the path to the fastd kernel device
	DevicePath = "/dev/fastd"
)

type KernelServer struct {
	dev       *os.File      // Interface to kernel
	recv      chan *Message // Received messages
	addresses []Sockaddr
}

func NewKernelServer(addresses []Sockaddr) (ServerImpl, error) {
	dev, err := os.OpenFile(DevicePath, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	srv := &KernelServer{
		dev:  dev,
		recv: make(chan *Message, 10),
	}

	for _, address := range addresses {
		// may fail
		srv.ioctl(ioctl_CLOSE, address)

		// tell the kernel module to bind to an address
		if err = srv.ioctl(ioctl_BIND, address); err != nil {
			srv.Close()
			return nil, fmt.Errorf("bind() failed: %s", err)
		}

		log.Printf("listening on %s, Port %d", address.IP.String(), address.Port)
		srv.addresses = append(srv.addresses, address)
	}

	go func() {
		err := srv.readPackets()
		if err != nil {
			log.Println("readPackets failed:", err)
		}
	}()

	return srv, nil
}

func (srv *KernelServer) ioctl(cmd uintptr, addr Sockaddr) error {
	sa := addr.RawFixed()
	return Ioctl(srv.dev.Fd(), cmd, uintptr(unsafe.Pointer(&sa)))
}

func (srv *KernelServer) Read() chan *Message {
	return srv.recv
}

func (srv *KernelServer) Close() {
	if srv.dev != nil {
		srv.dev.Close()
	}
	close(srv.recv)
}

// Iterates over existing interfaces and returns the peers
func (srv *KernelServer) Peers() (peers []*Peer) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Println("failed to load interfaces:", err)
		return
	}
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "fastd") {
			remote, pubkey, err := GetRemote(iface.Name)
			if err == nil {
				peers = append(peers, &Peer{
					Ifname:    iface.Name,
					Remote:    remote,
					PublicKey: pubkey,
				})
				log.Printf("loaded existing session: iface=%s remote=%v pubkey=%x", iface.Name, remote, pubkey)
			} else {
				log.Printf("failed to load session: iface=%s", iface.Name)
			}
		}
	}
	return
}

func (srv *KernelServer) readPackets() error {
	buf := make([]byte, 1500)

	pollFds := []unix.PollFd{{
		Fd:     int32(srv.dev.Fd()),
		Events: unix.POLLIN | unix.POLLERR | unix.POLLHUP,
	}}

	for {
		n, err := srv.dev.Read(buf)

		switch err {
		case nil:
			data := make([]byte, n)
			copy(data, buf[:n])
			if err = srv.read(data); err != nil {
				log.Println(err)
			}
		case io.EOF:
			num, e := unix.Poll(pollFds, 60*1000)

			// Error and not interrupted system call ?
			if e != nil && e != syscall.EINTR {
				return fmt.Errorf("syscall.SYS_POLL failed: %s", err)
			}

			if num < 0 {
				return fmt.Errorf("poll failed: %d (errno: %v)", num, e)
			}

			if num > 0 && pollFds[0].Revents&unix.POLLHUP != 0 {
				// disconnected
				return fmt.Errorf("device closed")
			}
		default:
			return err
		}

	}
}

func (srv *KernelServer) read(buf []byte) error {
	// check size
	if len(buf) < 40 {
		return fmt.Errorf("packet too small (%d bytes)", len(buf))
	}

	msg, err := ParseMessage(buf, true)
	if err != nil {
		return fmt.Errorf("unmarshal failed: %v", err)
	}

	srv.recv <- msg
	return nil
}

func (srv *KernelServer) Write(msg *Message) error {
	bytes := msg.Marshal(true)
	_, err := srv.dev.Write(bytes)
	return err
}
