package fastd

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// DevicePath is the path to the fastd kernel device
const DevicePath = "/dev/fastd"

// KernelServer implements a fastd server using a kernel module.
type KernelServer struct {
	dev       *os.File      // Interface to kernel
	recv      chan *Message // Received messages
	addresses []Sockaddr
	cancel    chan struct{}
}

// NewKernelServer creates a kernel based server.
func NewKernelServer(addresses []Sockaddr) (ServerImpl, error) {
	dev, err := os.OpenFile(DevicePath, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	srv := &KernelServer{
		dev:    dev,
		recv:   make(chan *Message, 10),
		cancel: make(chan struct{}),
	}

	for _, address := range addresses {
		// may fail
		srv.ioctl(ioctl_CLOSE, address)

		// tell the kernel module to bind to an address
		if err = srv.ioctl(ioctl_BIND, address); err != nil {
			srv.Close()
			return nil, errors.Wrapf(err, "binding to %v failed", address)
		}

		bind := net.JoinHostPort(address.IP.String(), strconv.Itoa(int(address.Port)))
		log.WithField("bind", bind).Info("start in-kernel server")
		srv.addresses = append(srv.addresses, address)
	}

	go func() {
		for {
			err := srv.readPackets()
			errors.Wrap(err, "readPackets failed")
			if err != nil {
				select {
				case <-srv.cancel:
					return
				case <-time.After(time.Second):
					// just waiting
				}
			}
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

// Close closes all client connections.
func (srv *KernelServer) Close() {
	close(srv.cancel)
	if srv.dev != nil {
		srv.dev.Close()
	}
	close(srv.recv)
}

// Peers iterates over existing interfaces and returns the peers.
func (srv *KernelServer) Peers() (peers []*Peer) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.WithError(err).Error("failed to load interfaces")
		return
	}
	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, "fastd") {
			remote, pubkey, err := GetRemote(iface.Name)
			if err != nil {
				log.WithFields(logrus.Fields{
					logrus.ErrorKey: err,
					"iface":         iface.Name,
				}).Error("failed to load session")
				continue
			}
			peers = append(peers, &Peer{
				Ifname:    iface.Name,
				Remote:    remote,
				PublicKey: pubkey,
			})
			log.WithFields(logrus.Fields{
				"iface":  iface.Name,
				"remote": remote,
				"pubkey": fmt.Sprintf("%x", pubkey),
			}).Info("loaded existing session")
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
				log.Errorf("%v", err)
			}
		case io.EOF:
			num, e := unix.Poll(pollFds, 60*1000)

			if e != nil {
				// Temp error, like interrupted system call (EINTR)?
				if errno, ok := e.(syscall.Errno); ok && errno.Temporary() {
					continue
				}

				// other error
				return errors.Wrap(e, "poll failed")
			}

			// num == 0 means timeout, can be ignored here
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
		return errors.Wrap(err, "unmarshal failed")
	}

	srv.recv <- msg
	return nil
}

func (srv *KernelServer) Write(msg *Message) error {
	bytes := msg.Marshal(true)
	_, err := srv.dev.Write(bytes)
	return err
}
