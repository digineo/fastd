#ifndef FASTD_IFACE_H
#define FASTD_IFACE_H


#include "fastd.h"

/* Maximum transmit packet size (default) */
#define	FASTDMTU		1406

#define FASTD_SOCKADDR_IS_IPV4(_vxsin)	((_vxsin)->sa.sa_family == AF_INET)
#define FASTD_SOCKADDR_IS_IPV6(_vxsin)	((_vxsin)->sa.sa_family == AF_INET6)
#define FASTD_SOCKADDR_IS_IPV46(_vxsin) \
    (FASTD_SOCKADDR_IS_IPV4(_vxsin) || FASTD_SOCKADDR_IS_IPV6(_vxsin))


#define FASTD_CMD_GET_CONFIG	0
#define FASTD_CMD_SET_REMOTE	1

struct iffastdcfg {
	struct fastd_inaddr	remote;
};

void fastd_iface_load(void);
void fastd_iface_unload(void);


#endif /* FASTD_IFACE_H */
