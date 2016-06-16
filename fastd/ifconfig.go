package fastd

/*
#include <stdlib.h>
*/
import "C"

import (
	"github.com/digineo/fastd/ifconfig"
	"net"
	"unsafe"
)

type IfaceStats struct {
	ipackets uint64
	opackets uint64
}

type ifconfigParam struct {
	pubkey [32]byte
	remote [18]byte
}

func SetAddrPTP(ifname string, addr, dstaddr net.IP) (err error) {
	return ifconfig.SetAddrPTP(ifname, addr, dstaddr)
}

const (
	FASTD_PARAM_GET_REMOTE = iota
	FASTD_PARAM_SET_REMOTE
	FASTD_PARAM_GET_STATS
)

// Get remote address and pubkey
func GetRemote(ifname string) (remote *Sockaddr, pubkey []byte, err error) {
	param := &ifconfigParam{}

	ifconfig.GetDrvSpec(ifname, FASTD_PARAM_GET_REMOTE, unsafe.Pointer(param), unsafe.Sizeof(*param))

	if err == nil {
		pubkey = param.pubkey[:]
		remote = parseSockaddr(param.remote[:])
	}

	return
}

func Clone(remote *Sockaddr, pubkey []byte) (string, error) {
	param := &ifconfigParam{remote: remote.RawFixed()}
	copy(param.pubkey[:], pubkey)
	return ifconfig.Clone("fastd", unsafe.Pointer(param))
}

// Set remote address and pubkey
func SetRemote(ifname string, remote *Sockaddr, pubkey []byte) error {
	param := &ifconfigParam{
		remote: remote.RawFixed(),
	}
	copy(param.pubkey[:], pubkey)

	return ifconfig.SetDrvSpec(ifname, FASTD_PARAM_SET_REMOTE, unsafe.Pointer(param), unsafe.Sizeof(*param))
}

// Get interface counter
func GetStats(ifname string) (*IfaceStats, error) {
	param := &IfaceStats{}

	err := ifconfig.GetDrvSpec(ifname, FASTD_PARAM_GET_STATS, unsafe.Pointer(param), unsafe.Sizeof(*param))

	return param, err
}
