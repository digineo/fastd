#ifndef FASTD_H
#define FASTD_H

#include <sys/types.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

MALLOC_DECLARE(M_FASTD);

#define FASTD_BIND          _IOW('F', 1, struct sockaddr_in)
#define FASTD_CLOSE         _IO('F', 2)

#define FASTD_MSG_BUFFER_SIZE 50
#define FASTD_MAX_DATA_SIZE   1024

extern struct buf_ring *fastd_msgbuf;
extern struct mtx       fastd_msgmtx;

// For both IPv4 and IPv6
union fastd_sockaddr {
  struct sockaddr sa;
  struct sockaddr_in  in4;
  struct sockaddr_in6 in6;
};

#define FASTD_HDR_CTRL  0x01
#define FASTD_HDR_DATA  0x02

// sockaddr + (header + data)
struct fastd_message {
  uint8_t              datalen;
  union fastd_sockaddr sockaddr;
  char                 data[0];
};

#endif /* FASTD_H */
