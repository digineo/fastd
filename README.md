
## Installation

### Kernel module

    svnlite checkout https://svn.FreeBSD.org/base/releng/10.3 /usr/src

    # cloning ...
    cd kmod
    make
    sudo kldload ./fastd.ko

### Daemon

    pkg install go pkgconf libuecc
    go get ...
    go install ...
