#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>

#define BUFFER_SIZE     256

#define FASTD_CLEAR_BUFFER       _IO('F', 1)

MALLOC_DECLARE(M_FASTD);
MALLOC_DEFINE(M_FASTD, "fastd_buffer", "buffer for fastd driver");

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

typedef struct fastd {
				char buffer[BUFFER_SIZE];
				int length;
} fastd_t;

static fastd_t *fastd_message;
static struct cdev *fastd_dev;

static int
fastd_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	int error = 0;

	error = copyin(uio->uio_iov->iov_base, fastd_message->buffer,
		MIN(uio->uio_iov->iov_len, BUFFER_SIZE - 1));
	if (error != 0) {
		uprintf("Write failed.\n");
		return (error);
	}

	*(fastd_message->buffer + MIN(uio->uio_iov->iov_len, BUFFER_SIZE - 1)) = 0;

	fastd_message->length = MIN(uio->uio_iov->iov_len, BUFFER_SIZE - 1);

	return (error);
}

static int
fastd_read(struct cdev *dev, struct uio *uio, int ioflag)
{
	int error = 0;
	int amount;

	amount = MIN(uio->uio_resid,
		(fastd_message->length - uio->uio_offset > 0) ?
		 fastd_message->length - uio->uio_offset : 0);

	error = uiomove(fastd_message->buffer + uio->uio_offset, amount, uio);
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
		fastd_message = malloc(sizeof(fastd_t), M_FASTD, M_WAITOK);
		fastd_dev = make_dev(&fastd_cdevsw, 0, UID_ROOT, GID_WHEEL,
			0600, "fastd");
		uprintf("fastd driver loaded.\n");
		break;
	case MOD_UNLOAD:
		destroy_dev(fastd_dev);
		free(fastd_message, M_FASTD);
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
	uprintf("command %lu\n", cmd);

	switch (cmd) {
	case FASTD_CLEAR_BUFFER:
		memset(fastd_message->buffer, '\0',
		fastd_message->length);
		fastd_message->length = 0;
		uprintf("Buffer cleared.\n");
		break;
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}


DEV_MODULE(fastd, fastd_modevent, NULL);
