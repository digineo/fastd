#ifndef FASTD_H
#define FASTD_H

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

MALLOC_DECLARE(M_FASTD);


// For both IPv4 and IPv6
typedef union {
  struct sockaddr sa;
  struct sockaddr_in  in4;
  struct sockaddr_in6 in6;
} fastd_sockaddr_t;

#define FASTD_HDR_HANDSHAKE	0x01
#define FASTD_HDR_DATA		0x02

typedef struct {
  char      addr[16]; // IPv4/IPv6 address
  in_port_t port;     // in network byte order
} fastd_inaddr_t;

// src + dst address + (header + data)
typedef struct {
  uint16_t		datalen;
  fastd_inaddr_t	src;
  fastd_inaddr_t	dst;
  char			data[];
} fastd_message_t;

#define FASTD_IOCTL_LIST	_IO('F', 1)
#define FASTD_IOCTL_BIND	_IOW('F', 2, fastd_inaddr_t)
#define FASTD_IOCTL_CLOSE	_IOW('F', 3, fastd_inaddr_t)

#define FASTD_MSG_BUFFER_SIZE	50
#define FASTD_MAX_DATA_SIZE	1024


#endif /* FASTD_H */
