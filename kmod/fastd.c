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

	uprintf("Written.\n");

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

		uprintf("fastd driver loaded.\n");
		break;
	case MOD_UNLOAD:
		fastd_destroy_socket();
		destroy_dev(fastd_dev);
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


DEV_MODULE(fastd, fastd_modevent, NULL);
