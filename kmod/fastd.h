#ifndef FASTD_H
#define FASTD_H

#include <sys/malloc.h>
#include <sys/ioccom.h>

#define FASTD_BIND          _IOW('F', 1, struct sockaddr_in)
#define FASTD_CLOSE         _IO('F', 2)

MALLOC_DECLARE(M_FASTD);
MALLOC_DEFINE(M_FASTD, "fastd_buffer", "buffer for fastd driver");

#endif /* FASTD_H */
