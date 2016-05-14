#ifndef FASTD_SOCKET_H
#define FASTD_SOCKET_H

#include "fastd.h"

int fastd_create_socket(void);
int fastd_bind_socket(union fastd_sockaddr* laddr);
void fastd_destroy_socket(void);

#endif /* FASTD_SOCKET_H */
