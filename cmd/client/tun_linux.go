package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

type linuxTunIface struct {
	iface *water.Interface
}

var _ Interface = (*linuxTunIface)(nil)

func (tun *linuxTunIface) Close() error {
	return tun.iface.Close()
}

func (tun *linuxTunIface) Name() string {
	return tun.iface.Name()
}

func (tun *linuxTunIface) Configure(mtu uint16, addresses ...*net.IPNet) error {
	link, err := netlink.LinkByName(tun.iface.Name())
	if err != nil {
		return err
	}

	for _, address := range addresses {
		netlink.AddrReplace(link, &netlink.Addr{IPNet: address})
	}

	netlink.LinkSetMTU(link, int(mtu))
	netlink.LinkSetUp(link)

	return nil // fmt.Errorf("not implemented yet")
}

func (tun *linuxTunIface) Read(p []byte) (n int, err error) {
	return tun.iface.Read(p)
}

func (tun *linuxTunIface) Write(p []byte) (n int, err error) {
	return tun.iface.Write(p)
}

func newTunDevice() (Interface, error) {
	config := water.Config{DeviceType: water.TUN}

	if name, err := findName("fastd"); err == nil {
		config.Name = name
	} else {
		return nil, err
	}

	iface, err := water.New(config)
	if err != nil {
		return nil, err
	}

	return &linuxTunIface{iface: iface}, nil
}

func findName(prefix string) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	samePrefix := make(map[string]struct{})
	mark := struct{}{}

	for _, iface := range ifaces {
		if strings.HasPrefix(iface.Name, prefix) {
			samePrefix[strings.TrimPrefix(iface.Name, prefix)] = mark
		}
	}

	var name string
	for id := 0; ; id++ {
		name = fmt.Sprintf("%s%d", prefix, id)
		if _, exists := samePrefix[name]; !exists {
			break
		}
	}
	return name, nil
}
