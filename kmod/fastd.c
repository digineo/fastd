#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>
#include <sys/socketvar.h>
#include <netinet/in.h>

// ringbuffer
#include <sys/param.h>
#include <sys/buf_ring.h>
#include <sys/mutex.h>

#include "fastd.h"
#include "socket.h"
#include "iface.h"

MALLOC_DEFINE(M_FASTD, "fastd_buffer", "buffer for fastd driver");

#define BUFFER_SIZE     256

/* Forward declarations. */
static d_read_t		fastd_read;
static d_write_t	fastd_write;
static d_ioctl_t	fastd_ioctl;

static struct cdevsw fastd_cdevsw = {
	.d_version =	D_VERSION,
	.d_read =	fastd_read,
	.d_write =	fastd_write,
	.d_ioctl =	fastd_ioctl,
	.d_name =	"fastd"
};

static struct cdev *fastd_dev;

struct buf_ring *fastd_msgbuf;
struct mtx       fastd_msgmtx;

static int
fastd_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	int error = 0;
	if (uio->uio_iov->iov_len < sizeof(struct fastd_message) - sizeof(uint16_t)){
		uprintf("message too short.\n");
		error = EINVAL;
		return (error);
	}

	error = fastd_send_packet(uio);

	return (error);
}

static int
fastd_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	int error = 0;
	struct fastd_message *msg;
	size_t tomove;

	// dequeue next message
	msg = buf_ring_dequeue_mc(fastd_msgbuf);

	if (msg != NULL) {
		// move message to device
		tomove = MIN(uio->uio_resid, sizeof(struct fastd_message) - sizeof(uint16_t) + msg->datalen);
		error  = uiomove((char *)msg + sizeof(uint16_t), tomove, uio);
		free(msg, M_FASTD);
	}

	if (error != 0)
		uprintf("Read failed.\n");

	return (error);
}

static int
fastd_modevent(module_t mod __unused, int event, void *arg __unused)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		mtx_init(&fastd_msgmtx, "fastd", NULL, MTX_SPIN);
		fastd_msgbuf = buf_ring_alloc(FASTD_MSG_BUFFER_SIZE, M_FASTD, M_WAITOK, &fastd_msgmtx);
		fastd_dev = make_dev(&fastd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "fastd");
		fastd_create_socket();
		fastd_iface_load();

		uprintf("fastd driver loaded.\n");
		break;
	case MOD_UNLOAD:
		fastd_iface_unload();
		fastd_destroy_socket();
		destroy_dev(fastd_dev);

		// Free ringbuffer and stored items
		struct fastd_message *msg;
		while(1){
			msg = buf_ring_dequeue_mc(fastd_msgbuf);
			if (msg == NULL)
				break;
			free(msg, M_FASTD);
		}
		buf_ring_free(fastd_msgbuf, M_FASTD);
		mtx_destroy(&fastd_msgmtx);

		uprintf("fastd driver unloaded.\n");
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

static int
fastd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag, struct thread *td)
{
	int error = 0;

	switch (cmd) {
	case FASTD_BIND:
		error = fastd_bind_socket((union fastd_sockaddr*)data);
		break;
	case FASTD_CLOSE:
		fastd_destroy_socket();
		break;
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}




int
isIPv4(const struct fastd_inaddr *inaddr){
  char *buf = (char *) inaddr;
  return (
       (char)0x00 == (buf[0] | buf[1] | buf[2] | buf[3] | buf[4] | buf[5]| buf[6] | buf[7] | buf[8] | buf[9])
    && (char)0xff == (buf[10] & buf[11])
  );
}

// Copies a fastd_inaddr into a fixed length fastd_sockaddr
void
sock_to_inet(struct fastd_inaddr *dst, const union fastd_sockaddr *src){
  switch (src->sa.sa_family) {
  case AF_INET:
    memset(        &dst->addr,      0x00, 10);
    memset((char *)&dst->addr + 10, 0xff, 2);
    memcpy((char *)&dst->addr + 12, &src->in4.sin_addr, 4);
    memcpy(        &dst->port,      &src->in4.sin_port, 2);
    break;
  case AF_INET6:
    memcpy(&dst->addr, &src->in6.sin6_addr, 16);
    memcpy(&dst->port, &src->in6.sin6_port, 2);
    break;
  default:
    panic("unsupported address family: %d", src->sa.sa_family);
  }
}

// Copies a fastd_sockaddr into fastd_inaddr
void
inet_to_sock(union fastd_sockaddr *dst, const struct fastd_inaddr *src){
  if (isIPv4(src)){
    // zero struct
    bzero(dst, sizeof(struct sockaddr_in));

    dst->in4.sin_len    = sizeof(struct sockaddr_in);
    dst->in4.sin_family = AF_INET;
    memcpy(&dst->in4.sin_addr, (char *)&src->addr + 12, 4);
    memcpy(&dst->in4.sin_port,         &src->port, 2);
  }else{
    // zero struct
    bzero(dst, sizeof(struct sockaddr_in6));

    dst->in6.sin6_len    = sizeof(struct sockaddr_in6);
    dst->in6.sin6_family = AF_INET6;
    memcpy(&dst->in6.sin6_addr, &src->addr, 16);
    memcpy(&dst->in6.sin6_port, &src->port, 2);
  }
}



DEV_MODULE(fastd, fastd_modevent, NULL);
