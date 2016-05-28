#ifndef FASTD_H
#define FASTD_H

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

MALLOC_DECLARE(M_FASTD);


// For both IPv4 and IPv6
union fastd_sockaddr {
  struct sockaddr sa;
  struct sockaddr_in  in4;
  struct sockaddr_in6 in6;
};

#define FASTD_HDR_CTRL  0x01
#define FASTD_HDR_DATA  0x02

struct fastd_inaddr {
  char      addr[16]; // IPv4/IPv6 address
  in_port_t port;     // in network byte order
};

// src + dst address + (header + data)
struct fastd_message {
  uint16_t            datalen;
  struct fastd_inaddr src;
  struct fastd_inaddr dst;
  char                data[];
};

#define FASTD_IOCTL_LIST          _IO('F', 1)
#define FASTD_IOCTL_BIND          _IOW('F', 2, struct fastd_inaddr)
#define FASTD_IOCTL_CLOSE         _IOW('F', 3, struct fastd_inaddr)

#define FASTD_MSG_BUFFER_SIZE 50
#define FASTD_MAX_DATA_SIZE   1024




#endif /* FASTD_H */
