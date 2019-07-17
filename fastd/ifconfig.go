package fastd

import (
	"net"
	"unsafe"

	"github.com/digineo/fastd/ifconfig"
)

// IfaceStats are counters for incoming and outgoing packets
type IfaceStats struct {
	ipackets uint64
	opackets uint64
}

type ifconfigParam struct {
	pubkey [32]byte
	remote [18]byte
}

// SetAddrPTP sets the local and remote Point-To-Point addresses
func SetAddrPTP(ifname string, addr, dstaddr net.IP) (err error) {
	return ifconfig.SetAddrPTP(ifname, addr, dstaddr)
}

const (
	paramGetRemote = iota
	paramSetRemote
	paramGetStats
)

// GetRemote returns the remote address and pubkey
func GetRemote(ifname string) (remote Sockaddr, pubkey []byte, err error) {
	param := &ifconfigParam{}

	ifconfig.GetDrvSpec(ifname, paramGetRemote, unsafe.Pointer(param), unsafe.Sizeof(*param))

	if err == nil {
		pubkey = param.pubkey[:]
		remote = parseSockaddr(param.remote[:])
	}

	return
}

// Clone creates a new fastd interface
func Clone(remote Sockaddr, pubkey []byte) (string, error) {
	param := &ifconfigParam{remote: remote.RawFixed()}
	copy(param.pubkey[:], pubkey)
	return ifconfig.Clone("fastd", unsafe.Pointer(param))
}

// SetRemote sets the remote address and pubkey
func SetRemote(ifname string, remote Sockaddr, pubkey []byte) error {
	param := &ifconfigParam{
		remote: remote.RawFixed(),
	}
	copy(param.pubkey[:], pubkey)

	return ifconfig.SetDrvSpec(ifname, paramSetRemote, unsafe.Pointer(param), unsafe.Sizeof(*param))
}

// GetStats returns the interface counters
func GetStats(ifname string) (*IfaceStats, error) {
	param := &IfaceStats{}

	err := ifconfig.GetDrvSpec(ifname, paramGetStats, unsafe.Pointer(param), unsafe.Sizeof(*param))

	return param, err
}
