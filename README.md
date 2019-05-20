# fastd

An implementation of the [fastd](https://projects.universe-factory.net/projects/fastd/wiki) VPN protocol for FreeBSD.
It consists of a kernel module and a user space daemon written in [Go](https://golang.org/).

## Features

* High performance
* TUN support (Layer 3)
* Dual-Stack (IPv4 + IPv6)
* FHMQV (Fully Hashed Menezes-Qu-Vanstone) key exchange
* Null Cipher (no encryption)


## Installation

### Kernel module

    svnlite checkout https://svn.FreeBSD.org/base/releng/12.0 /usr/src

    # cloning ...
    cd kmod
    make
    sudo kldload ./fastd.ko

To create a debug build:

    make DEBUG_FLAGS=-DDEBUG

### Daemon

    go get github.com/digineo/fastd
    go install github.com/digineo/fastd
