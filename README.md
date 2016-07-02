# fastd


## Features

* High performance
* TUN support (Layer 3)
* Dual-Stack (IPv4 + IPv6)
* FHMQV (Fully Hashed Menezes-Qu-Vanstone) key exchange
* Null Cipher (no encryption)


## Installation

### Kernel module

    svnlite checkout https://svn.FreeBSD.org/base/releng/10.3 /usr/src

    # cloning ...
    cd kmod
    make
    sudo kldload ./fastd.ko

To create a debug build:

    make DEBUG_FLAGS=-DDEBUG

### Daemon

    pkg install go pkgconf libuecc
    go get ...
    go install ...
