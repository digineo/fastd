#ifndef FASTD_SOCKET_H
#define FASTD_SOCKET_H

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

union fastd_sockaddr {
  struct sockaddr sa;
  struct sockaddr_in  in4;
  struct sockaddr_in6 in6;
};


struct fastd_header {
  uint8_t   fdh_type;
#define FASTD_HDR_CTRL  0x01
#define FASTD_HDR_DATA  0x02
  uint8_t   fdh_dummy;
  uint16_t  fdh_length;
};

int fastd_create_socket(void);
int fastd_bind_socket(union fastd_sockaddr* laddr);
void fastd_destroy_socket(void);

#endif /* FASTD_SOCKET_H */
