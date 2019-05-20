#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/event.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>
#include <sys/socketvar.h>
#include <sys/param.h>
#include <sys/buf_ring.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/sysctl.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/hash.h>
#include <sys/lock.h>
#include <sys/rmlock.h>

#include <net/if.h>
#include <net/if_var.h>
#include <net/if_clone.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/bpf.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include "fastd.h"

#ifdef DEBUG
#define DEBUGF(fmt, ...) printf("%s(): " fmt "\n", __func__, ##__VA_ARGS__);
#define IFP_DEBUG(ifp, fmt, ...) if_printf(ifp, "%s(): " fmt "\n", __func__, ##__VA_ARGS__);
#else
#define DEBUGF(...)
#define IFP_DEBUG(...)
#endif

/* Maximum output packet size (default) */
#define	FASTD_MTU		1406
#define	FASTD_PUBKEY_SIZE	32

/* Number of handshake packets in the ringbuffer */
#define FASTD_MSG_BUFFER_SIZE	50

#define FASTD_SOCKADDR_IS_IPV4(_sin) ((_sin)->sa.sa_family == AF_INET)
#define FASTD_SOCKADDR_IS_IPV6(_sin) ((_sin)->sa.sa_family == AF_INET6)
#define FASTD_SOCKADDR_IS_IPV46(_sin) (FASTD_SOCKADDR_IS_IPV4(_sin) || FASTD_SOCKADDR_IS_IPV6(_sin))

#define FASTD_HASH_SHIFT	6
#define FASTD_HASH_SIZE		(1 << FASTD_HASH_SHIFT)
#define FASTD_HASH_ADDR(_sa)	((_sa)->in4.sin_port % FASTD_HASH_SIZE)
#define FASTD_HASH(_sc)		((_sc)->remote.in4.sin_port % FASTD_HASH_SIZE)

// SIOCGDRVSPEC/SIOCSDRVSPEC commands on fastd interface
#define FASTD_CMD_GET_REMOTE	0
#define FASTD_CMD_SET_REMOTE	1
#define FASTD_CMD_GET_STATS	2


#define FASTD_RLOCK(_sc, _p)	rm_rlock(&(_sc)->lock, (_p))
#define FASTD_RUNLOCK(_sc, _p)	rm_runlock(&(_sc)->lock, (_p))
#define FASTD_WLOCK(_sc)	rm_wlock(&(_sc)->lock)
#define FASTD_WUNLOCK(_sc)	rm_wunlock(&(_sc)->lock)
#define FASTD_ACQUIRE(_sc)	refcount_acquire(&(_sc)->refcnt)
#define FASTD_RELEASE(_sc)	refcount_release(&(_sc)->refcnt)

struct iffastdcfg {
	char			pubkey[FASTD_PUBKEY_SIZE];
	fastd_inaddr_t	remote;
};

struct iffastdstats {
	u_long	ipackets;
	u_long	opackets;
};

static void fastd_iface_load(void);
static void fastd_iface_unload(void);


MALLOC_DEFINE(M_FASTD, "fastd_buffer", "buffer for fastd driver");

/* Forward declarations. */
static d_read_t		fastd_read;
static d_write_t	fastd_write;
static d_ioctl_t	fastd_ioctl;
static d_poll_t		fastd_poll;
static d_kqfilter_t	fastd_kqfilter;
static int		fastd_kqevent(struct knote *, long);
static void		fastd_kqdetach(struct knote *);

static struct filterops fastd_filterops = {
	.f_isfd =	0,
	.f_attach =	NULL,
	.f_detach =	fastd_kqdetach,
	.f_event =	fastd_kqevent,
};

static struct cdevsw fastd_cdevsw = {
	.d_version =	D_VERSION,
	.d_read =	fastd_read,
	.d_write =	fastd_write,
	.d_ioctl =	fastd_ioctl,
	.d_poll =	fastd_poll,
	.d_kqfilter =	fastd_kqfilter,
	.d_name =	"fastd"
};

static const char fastdname[] = "fastd";

static struct if_clone	*fastd_cloner;
static struct cdev	*fastd_dev;
static struct buf_ring	*fastd_msgbuf;
static struct rmlock	fastd_lock;
static struct mtx	fastd_msgmtx;
static struct selinfo	fastd_rsel;

struct fastdudphdr {
	struct udphdr	fastd_udp;
	char type;
} __packed;

// ------------------------------------
// Kernel Sockets

struct fastd_socket {
	LIST_ENTRY(fastd_socket) list;
	LIST_HEAD(,fastd_softc) softc_head; // List of all assigned interfaces
	struct socket        *socket;
	fastd_sockaddr_t  laddr;
};
typedef struct fastd_socket fastd_socket_t;

// Head of all kernel sockets
static LIST_HEAD(,fastd_socket) fastd_sockets_head = LIST_HEAD_INITIALIZER(fastd_socket);


// ------------------------------------
// Network Interfaces

struct fastd_softc {
	// lists are protected by global fastd_lock
	LIST_ENTRY(fastd_softc) fastd_ifaces;		/* list of all interfaces */
	LIST_ENTRY(fastd_softc) fastd_flow_entry;	/* entry in flow table */
	LIST_ENTRY(fastd_softc) fastd_socket_entry;	/* list of softc for a socket */

	struct ifnet		*ifp;		/* the interface */
	fastd_socket_t		*socket;	/* socket for outgoing packets */
	fastd_sockaddr_t	remote;		/* remote ip address and port */
	struct rmlock		lock;		/* to wait for the refcounter */
	volatile u_int		refcnt;		/* reference counter */
	char			pubkey[FASTD_PUBKEY_SIZE]; /* public key of the peer */
	uint32_t		flags;
#define FASTD_FLAG_TEARDOWN	0x0001
};
typedef struct fastd_softc fastd_softc_t;

// Head of all fastd interfaces
static LIST_HEAD(,fastd_softc) fastd_ifaces_head = LIST_HEAD_INITIALIZER(fastd_softc);

// Mapping from source addresses to interfaces
LIST_HEAD(fastd_softc_head, fastd_softc);
struct fastd_softc_head fastd_peers[FASTD_HASH_SIZE];


static void		fastd_release(fastd_softc_t *);
static int		fastd_bind_socket(fastd_sockaddr_t*);
static int		fastd_close_socket(fastd_sockaddr_t*);
static void		fastd_close_sockets(void);
static fastd_socket_t*	fastd_find_socket(const fastd_sockaddr_t*);
static fastd_socket_t*	fastd_find_socket_locked(const fastd_sockaddr_t*);
static int		fastd_send_packet(struct uio *uio);

static void	fastd_rcv_udp_packet(struct mbuf *, int, struct inpcb *, const struct sockaddr *, void *);
static void	fastd_recv_data(struct mbuf *, u_int, u_int, fastd_softc_t *);

static int	fastd_clone_create(struct if_clone *, int, caddr_t);
static void	fastd_clone_destroy(struct ifnet *);
static void	fastd_teardown(fastd_softc_t *sc);
static void	fastd_destroy(fastd_softc_t *sc);
static int	fastd_ifioctl(struct ifnet *, u_long, caddr_t);
static int	fastd_ioctl_drvspec(fastd_softc_t *, struct ifdrv *, int);
static void	fastd_ifinit(struct ifnet *);
static void	fastd_ifstart(struct ifnet *);
static int	fastd_output(struct ifnet *, struct mbuf *, const struct sockaddr *, struct route *ro);
static void	fastd_encap_header(fastd_softc_t *, struct mbuf *, int, uint16_t, uint16_t);
static int	fastd_encap4(fastd_softc_t *, const fastd_sockaddr_t *, struct mbuf *);
static int	fastd_encap6(fastd_softc_t *, const fastd_sockaddr_t *, struct mbuf *);

static int	fastd_add_peer(fastd_softc_t *, fastd_sockaddr_t *, char [FASTD_PUBKEY_SIZE]);
static void	fastd_remove_peer(fastd_softc_t *);
static struct	fastd_softc* fastd_lookup_peer(const fastd_sockaddr_t *);

static void	fastd_sockaddr_copy(fastd_sockaddr_t *, const fastd_sockaddr_t *);
static int	fastd_sockaddr_equal(const fastd_sockaddr_t *, const fastd_sockaddr_t *);

static int	fastd_ctrl_get_remote(fastd_softc_t *, void *);
static int	fastd_ctrl_set_remote(fastd_softc_t *, void *);
static int	fastd_ctrl_get_stats(fastd_softc_t *, void *);

struct fastd_control {
	int (*fastdc_func)(fastd_softc_t *, void *);
	int fastdc_argsize;
	int fastdc_flags;
#define FASTD_CTRL_FLAG_COPYIN  0x01
#define FASTD_CTRL_FLAG_COPYOUT 0x02
};




// ------------------------------------------------------------------
// Socket helper functions
// ------------------------------------------------------------------


// Copies a fastd_inaddr into a fixed length fastd_sockaddr
static inline void
sock_to_inet(fastd_inaddr_t *dst, const fastd_sockaddr_t *src){
	switch (src->sa.sa_family) {
	case AF_INET:
		bzero(dst->addr, 10);
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
static inline void
inet_to_sock(fastd_sockaddr_t *dst, const fastd_inaddr_t *src){
	if (IN6_IS_ADDR_V4MAPPED((const struct in6_addr *)src)){
		// zero struct
		bzero(dst, sizeof(struct sockaddr_in));

		dst->in4.sin_len    = sizeof(struct sockaddr_in);
		dst->in4.sin_family = AF_INET;
		memcpy(&dst->in4.sin_addr, (const char *)&src->addr + 12, 4);
		memcpy(&dst->in4.sin_port,               &src->port, 2);
	}else{
		// zero struct
		bzero(dst, sizeof(struct sockaddr_in6));

		dst->in6.sin6_len    = sizeof(struct sockaddr_in6);
		dst->in6.sin6_family = AF_INET6;
		memcpy(&dst->in6.sin6_addr, &src->addr, 16);
		memcpy(&dst->in6.sin6_port, &src->port, 2);
	}
}



// copy fastd_sockaddr to fastd_sockaddr
static inline void
fastd_sockaddr_copy(fastd_sockaddr_t *dst, const fastd_sockaddr_t *src)
{
	switch (src->sa.sa_family) {
	case AF_INET:
		memcpy(dst, src, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		memcpy(dst, src, sizeof(struct sockaddr_in6));
		break;
	}
}



// compares fastd_sockaddr with another fastd_sockaddr
static inline int
fastd_sockaddr_equal(const fastd_sockaddr_t *a, const fastd_sockaddr_t *b)
{
	if (a->sa.sa_family != b->sa.sa_family)
		return 0;

	switch (a->sa.sa_family) {
	case AF_INET:
		return (
			a->in4.sin_addr.s_addr == b->in4.sin_addr.s_addr &&
			a->in4.sin_port == b->in4.sin_port
		);
	case AF_INET6:
		return (
			IN6_ARE_ADDR_EQUAL (&a->in6.sin6_addr, &b->in6.sin6_addr) &&
			(a->in6.sin6_port == b->in6.sin6_port) &&
			(a->in6.sin6_scope_id == 0 || b->in6.sin6_scope_id == 0 || (a->in6.sin6_scope_id == b->in6.sin6_scope_id))
		);
	default:
		return 1;
	}
}

// Returns whether the given IP address is unspecified
static inline int
fastd_sockaddr_unspecified(const fastd_sockaddr_t *sa)
{
	switch (sa->sa.sa_family) {
	case AF_INET:
		return sa->in4.sin_addr.s_addr == 0;
	case AF_INET6:
		return IN6_IS_ADDR_UNSPECIFIED(&sa->in6.sin6_addr);
	default:
		return -1;
	}
}


// ------------------------------------------------------------------
// Functions for control device
// ------------------------------------------------------------------


static int
fastd_poll(struct cdev *dev, int events, struct thread *td)
{
	int revents;

	mtx_lock(&fastd_msgmtx);
	if (buf_ring_empty(fastd_msgbuf)) {
		revents = 0;
		if (events & (POLLIN | POLLRDNORM))
			selrecord(td, &fastd_rsel);
	} else {
		revents = events & (POLLIN | POLLRDNORM);
	}
	mtx_unlock(&fastd_msgmtx);
	return (revents);
}

static int
fastd_kqfilter(struct cdev *dev, struct knote *kn)
{
	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &fastd_filterops;
		knlist_add(&fastd_rsel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static int
fastd_kqevent(struct knote *kn, long hint)
{
	kn->kn_data = buf_ring_count(fastd_msgbuf);
	return (kn->kn_data > 0);
}

static void
fastd_kqdetach(struct knote *kn)
{
	knlist_remove(&fastd_rsel.si_note, kn, 0);
}

static int
fastd_write(struct cdev *dev, struct uio *uio, int ioflag)
{
	int error = 0;
	if (uio->uio_iov->iov_len < sizeof(fastd_message_t) - sizeof(uint16_t)){
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
	fastd_message_t *msg;
	size_t tomove;

	// dequeue next message
	msg = buf_ring_dequeue_mc(fastd_msgbuf);

	if (msg != NULL) {
		// move message to device
		tomove = MIN(uio->uio_resid, sizeof(fastd_message_t) - sizeof(uint16_t) + msg->datalen);
		error  = uiomove((char *)msg + sizeof(uint16_t), tomove, uio);
		free(msg, M_FASTD);
	}

	if (error)
		uprintf("Read failed.\n");

	return (error);
}

static int
fastd_modevent(module_t mod __unused, int event, void *arg __unused)
{
	int error = 0;

	switch (event) {
	case MOD_LOAD:
		rm_init(&fastd_lock, "fastd_lock");
		mtx_init(&fastd_msgmtx, "fastd", NULL, MTX_SPIN);
		knlist_init_mtx(&fastd_rsel.si_note, NULL);
		fastd_msgbuf = buf_ring_alloc(FASTD_MSG_BUFFER_SIZE, M_FASTD, M_WAITOK, &fastd_msgmtx);
		fastd_dev = make_dev(&fastd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "fastd");
		fastd_iface_load();

		uprintf("fastd driver loaded.\n");
		break;
	case MOD_UNLOAD:
		fastd_iface_unload();
		fastd_close_sockets();
		knlist_destroy(&fastd_rsel.si_note);
		seldrain(&fastd_rsel);
		destroy_dev(fastd_dev);

		// Free ringbuffer and stored items
		fastd_message_t *msg;
		while(1){
			msg = buf_ring_dequeue_mc(fastd_msgbuf);
			if (msg == NULL)
				break;
			free(msg, M_FASTD);
		}
		buf_ring_free(fastd_msgbuf, M_FASTD);
		mtx_destroy(&fastd_msgmtx);
		rm_destroy(&fastd_lock);

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
	int error;
	fastd_sockaddr_t sa;

	switch (cmd) {
	case FASTD_IOCTL_BIND:
		inet_to_sock(&sa, (fastd_inaddr_t*)data);
		error = fastd_bind_socket(&sa);
		break;
	case FASTD_IOCTL_CLOSE:
		inet_to_sock(&sa, (fastd_inaddr_t*)data);
		error = fastd_close_socket(&sa);
		break;
	default:
		error = ENOTTY;
		break;
	}

	return (error);
}


DEV_MODULE(fastd, fastd_modevent, NULL);


// ------------------------------------------------------------------
// Locking
// ------------------------------------------------------------------


static void
fastd_release(fastd_softc_t *sc)
{

	/*
	 * The softc may be destroyed as soon as we release our reference,
	 * so we cannot serialize the wakeup with the softc lock. We use a
	 * timeout in our sleeps so a missed wakeup is unfortunate but not
	 * fatal.
	 */
	if (FASTD_RELEASE(sc) != 0)
		wakeup(sc);
}


// ------------------------------------------------------------------
// Network functions
// ------------------------------------------------------------------



static int
fastd_bind_socket(fastd_sockaddr_t *sa){
	int error;
	fastd_socket_t *sock;

	if (fastd_sockaddr_unspecified(sa)){
		return EADDRNOTAVAIL;
	}

	sock = malloc(sizeof(*sock), M_FASTD, M_WAITOK | M_ZERO);
	fastd_sockaddr_copy(&sock->laddr, sa);

	error = socreate(sa->sa.sa_family, &sock->socket, SOCK_DGRAM, IPPROTO_UDP, curthread->td_ucred, curthread);

	if (error) {
		goto out;
	}

	error = sobind(sock->socket, &sa->sa, curthread);

	if (error) {
		uprintf("cannot bind to socket: %d\n", error);
		goto fail;
	}

	error = udp_set_kernel_tunneling(sock->socket, fastd_rcv_udp_packet, NULL, sock);

	if (error) {
		uprintf("cannot set tunneling function: %d\n", error);
		goto fail;
	}

	// Initialize list of assigned interfaces
	LIST_INIT(&sock->softc_head);

	// Add to list of sockets
	rm_wlock(&fastd_lock);
	LIST_INSERT_HEAD(&fastd_sockets_head, sock, list);
	rm_wunlock(&fastd_lock);

	goto out;

fail:
	soclose(sock->socket);
out:
	if (error) {
		free(sock, M_FASTD);
	}

	return (error);
}


// Closes a socket
static int
fastd_close_socket(fastd_sockaddr_t *sa){
	int error = ENXIO;
	fastd_socket_t *sock;

	rm_wlock(&fastd_lock);

	LIST_FOREACH(sock, &fastd_sockets_head, list) {
		if (fastd_sockaddr_equal(sa, &sock->laddr)) {
			soclose(sock->socket);
			free(sock, M_FASTD);
			LIST_REMOVE(sock, list);
			error = 0;
			break;
		}
	}

	rm_wunlock(&fastd_lock);
	return (error);
}


// Closes all sockets
static void
fastd_close_sockets(){
	fastd_socket_t *sock;

	rm_wlock(&fastd_lock);

	LIST_FOREACH(sock, &fastd_sockets_head, list) {
		soclose(sock->socket);
		free(sock, M_FASTD);
	}
	LIST_INIT(&fastd_sockets_head);

	rm_wunlock(&fastd_lock);
}


// Finds a socket by sockaddr
static fastd_socket_t *
fastd_find_socket(const fastd_sockaddr_t *sa){
	struct rm_priotracker tracker;
	fastd_socket_t *sock;

	rm_rlock(&fastd_lock, &tracker);
	sock = fastd_find_socket_locked(sa);
	rm_runlock(&fastd_lock, &tracker);
	return sock;
}

// Finds a socket by sockaddr
static fastd_socket_t *
fastd_find_socket_locked(const fastd_sockaddr_t *sa){
	fastd_socket_t *sock;

	LIST_FOREACH(sock, &fastd_sockets_head, list) {
		//if (fastd_sockaddr_equal(sa, &sock->laddr))

		// Find by sa_family
		if (sa->sa.sa_family == sock->laddr.sa.sa_family)
			return sock;
	}
	return NULL;
}

inline static int
fastd_encap(fastd_softc_t *sc, const fastd_sockaddr_t *dst, struct mbuf *m)
{

	if (dst->sa.sa_family == AF_INET)
		return fastd_encap4(sc, dst, m);
	else
		return fastd_encap6(sc, dst, m);
}



static void
fastd_encap_header(fastd_softc_t *sc, struct mbuf *m, int ipoff, uint16_t srcport, uint16_t dstport)
{
	struct fastdudphdr *hdr;
	int len;

	len = m->m_pkthdr.len - ipoff;
	MPASS(len >= sizeof(struct fastdudphdr));
	hdr = mtodo(m, ipoff);

	hdr->fastd_udp.uh_sport = srcport;
	hdr->fastd_udp.uh_dport = dstport;
	hdr->fastd_udp.uh_ulen = htons(len);
	hdr->fastd_udp.uh_sum = 0;

	// Set fastd packet type to data
	hdr->type = FASTD_HDR_DATA;
}

static int
fastd_encap4(fastd_softc_t *sc, const fastd_sockaddr_t *dst, struct mbuf *m)
{
	struct ifnet *ifp;
	struct ip *ip;
	struct in_addr srcaddr, dstaddr;
	uint16_t srcport, dstport;
	int len, error;

	ifp = sc->ifp;

	srcaddr = sc->socket->laddr.in4.sin_addr;
	srcport = sc->socket->laddr.in4.sin_port;
	dstaddr = dst->in4.sin_addr;
	dstport = dst->in4.sin_port;

	M_PREPEND(m, sizeof(struct ip) + sizeof(struct fastdudphdr), M_NOWAIT);
	if (m == NULL) {
		IFP_DEBUG(ifp, "ENOBUFS");
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENOBUFS);
	}

	len = m->m_pkthdr.len;

	ip = mtod(m, struct ip *);
	ip->ip_tos = 0;
	ip->ip_len = htons(len);
	ip->ip_off = 0;
	ip->ip_ttl = IPDEFTTL;
	ip->ip_p   = IPPROTO_UDP;
	ip->ip_sum = 0;
	ip->ip_src = srcaddr;
	ip->ip_dst = dstaddr;

	fastd_encap_header(sc, m, sizeof(struct ip), srcport, dstport);

	error = ip_output(m, NULL, NULL, 0, NULL, NULL);
	if (error == 0) {
		if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
		if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
	} else
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);

	return (error);
}

static int
fastd_encap6(fastd_softc_t *sc, const fastd_sockaddr_t *dst, struct mbuf *m)
{
	struct ifnet *ifp;
	struct ip6_hdr *ip6;
	const struct in6_addr *srcaddr, *dstaddr;
	uint16_t srcport, dstport;
	int len, error;

	ifp = sc->ifp;

	srcaddr = &sc->socket->laddr.in6.sin6_addr;
	srcport = sc->socket->laddr.in6.sin6_port;
	dstaddr = &dst->in6.sin6_addr;
	dstport = dst->in6.sin6_port;

	M_PREPEND(m, sizeof(struct ip6_hdr) + sizeof(struct fastdudphdr), M_NOWAIT);
	if (m == NULL) {
		IFP_DEBUG(ifp, "ENOBUFS");
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);
		return (ENOBUFS);
	}

	len = m->m_pkthdr.len;

	ip6 = mtod(m, struct ip6_hdr *);
	ip6->ip6_flow = 0;
	ip6->ip6_vfc  = IPV6_VERSION;
	ip6->ip6_plen = 0;
	ip6->ip6_nxt  = IPPROTO_UDP;
	ip6->ip6_hlim = IPV6_DEFHLIM;
	ip6->ip6_src  = *srcaddr;
	ip6->ip6_dst  = *dstaddr;

	fastd_encap_header(sc, m, sizeof(struct ip6_hdr), srcport, dstport);

	/*
	 * XXX BMV We need support for RFC6935 before we can send and
	 * receive IPv6 UDP packets with a zero checksum.
	 */
	{
		struct udphdr *hdr = mtodo(m, sizeof(struct ip6_hdr));
		hdr->uh_sum = in6_cksum_pseudo(ip6, m->m_pkthdr.len - sizeof(struct ip6_hdr), IPPROTO_UDP, 0);
		m->m_pkthdr.csum_flags = CSUM_UDP_IPV6;
		m->m_pkthdr.csum_data = offsetof(struct udphdr, uh_sum);
	}

	error = ip6_output(m, NULL, NULL, 0, NULL, NULL, NULL);
	if (error == 0) {
		if_inc_counter(ifp, IFCOUNTER_OPACKETS, 1);
		if_inc_counter(ifp, IFCOUNTER_OBYTES, len);
	} else
		if_inc_counter(ifp, IFCOUNTER_OERRORS, 1);

	return (error);
}


static void
fastd_rcv_udp_packet(struct mbuf *m, int offset, struct inpcb *inpcb,
		const struct sockaddr *sa_src, void *xfso)
{
	struct rm_priotracker tracker;
	fastd_message_t *fastd_msg;
	fastd_socket_t *fso;
	fastd_softc_t *sc;
	char msg_type;
	int error;
	u_int datalen;

	// Ensure packet header exists
	M_ASSERTPKTHDR(m);

	fso = xfso;
	offset += sizeof(struct udphdr);
	datalen = m->m_len - offset;

	// drop UDP packets with less than 1 byte payload
	if (datalen < 1)
		goto out;

	m_copydata(m, offset, 1, (caddr_t) &msg_type);
	rm_rlock(&fastd_lock, &tracker);

	switch (msg_type){
	case FASTD_HDR_HANDSHAKE:
		// Header too short?
		if (datalen < 4)
			goto out;

		// Allocate memory
		fastd_msg = malloc(sizeof(*fastd_msg) + datalen, M_FASTD, M_NOWAIT);
		if (fastd_msg == NULL)
			goto out;
		fastd_msg->datalen = datalen;

		// Copy addresses
		sock_to_inet(&fastd_msg->src, (const fastd_sockaddr_t *)sa_src);
		sock_to_inet(&fastd_msg->dst, &fso->laddr);

		// Copy fastd packet
		m_copydata(m, offset, datalen, (caddr_t) &fastd_msg->data);

		// Store into ringbuffer of character device
		error = buf_ring_enqueue(fastd_msgbuf, fastd_msg);
		if (error == ENOBUFS){
			printf("fastd: no buffer for handshake packets available\n");
			free(fastd_msg, M_FASTD);
		} else {
			selwakeup(&fastd_rsel);
			KNOTE_UNLOCKED(&fastd_rsel.si_note, 0);
		}

		break;
	case FASTD_HDR_DATA:

		sc = fastd_lookup_peer((const fastd_sockaddr_t *)sa_src);
		if (sc == NULL) {
			DEBUGF("unable to find peer");
			goto out;
		}
		if ((sc->ifp->if_drv_flags & IFF_DRV_RUNNING) == 0){
			IFP_DEBUG(sc->ifp, "not running");
			goto out;
		}

		FASTD_ACQUIRE(sc);
		rm_runlock(&fastd_lock, &tracker);
		fastd_recv_data(m, offset, datalen, sc);
		fastd_release(sc);

		// unlock/free already done
		return;
	default:
		DEBUGF("invalid packet type=%02X datalen=%d", msg_type, datalen);
	}
out:
	rm_runlock(&fastd_lock, &tracker);
	m_freem(m);
}

static void
fastd_recv_data(struct mbuf *m, u_int offset, u_int datalen, fastd_softc_t *sc)
{
	int isr, af;

	if (datalen == 1){
		// Keepalive packet
		IFP_DEBUG(sc->ifp, "keepalive received");
		if_inc_counter(sc->ifp, IFCOUNTER_IPACKETS, 1);

		// Remove headers, which results in an empty packet
		m_adj(m, offset+1);
		int error = fastd_encap(sc, &sc->remote, m);

		if (error) {
			IFP_DEBUG(sc->ifp, "keepalive response failed: %d", error);
		} else {
			IFP_DEBUG(sc->ifp, "keepalive replied");
		}
		return;
	}

	IFP_DEBUG(sc->ifp, "data received");

	// Get the IP version number
	u_int8_t tp;
	m_copydata(m, offset+1, 1, &tp);
	tp = (tp >> 4) & 0xff;

	switch (tp) {
	case IPVERSION:
		isr = NETISR_IP;
		af = AF_INET;
		break;
	case (IPV6_VERSION >> 4):
		isr = NETISR_IPV6;
		af = AF_INET6;
		break;
	default:
		if_inc_counter(sc->ifp, IFCOUNTER_IERRORS, 1);
		IFP_DEBUG(sc->ifp, "unknown ip version: %02x", tp );
		m_freem(m);
		return;
	}

	// Trim ip+udp+fastd headers
	m_adj(m, offset+1);

	// Assign receiving interface
	m->m_pkthdr.rcvif = sc->ifp;

	// Pass to Berkeley Packet Filter
	BPF_MTAP2(sc->ifp, &af, sizeof(af), m);

	// Update counters
	if_inc_counter(sc->ifp, IFCOUNTER_IPACKETS, 1);
	if_inc_counter(sc->ifp, IFCOUNTER_IBYTES, m->m_pkthdr.len);

	netisr_dispatch(isr, m);
}

// Send outgoing control packet via UDP
static int
fastd_send_packet(struct uio *uio) {
	int error;
	size_t datalen, addrlen;
	fastd_message_t msg;
	struct mbuf *m = NULL;
	fastd_socket_t *sock;
	fastd_sockaddr_t src_addr, dst_addr;


	addrlen = 2 * sizeof(fastd_inaddr_t);
	datalen = uio->uio_iov->iov_len - addrlen;

	// Copy addresses from user memory
	error = uiomove((char *)&msg + sizeof(uint16_t), addrlen, uio);
	if (error) {
		goto out;
	}

	// Build destination address
	inet_to_sock(&src_addr, &msg.src);
	inet_to_sock(&dst_addr, &msg.dst);

	// Find socket by address
	sock = fastd_find_socket(&src_addr);
	if (sock == NULL) {
	error = EIO;
		goto out;
	}

	// Allocate space for packet
	m = m_getm(NULL, datalen, M_WAITOK, MT_DATA);

	// Set mbuf current data length
	m->m_len = m->m_pkthdr.len = datalen;

	// Copy payload from user memory
	error = uiomove(m->m_data, datalen, uio);
	if (error) {
		goto fail;
	}

	// Send packet
	error = sosend(sock->socket, &dst_addr.sa, NULL, m, NULL, 0, uio->uio_td);
	if (error) {
		goto fail;
	}

	goto out;
fail:
	m_free(m);
out:
	return (error);
}

static int
fastd_output(struct ifnet *ifp, struct mbuf *m, const struct sockaddr *dst, struct route *ro)
{
	int error;
	struct rm_priotracker tracker;
	fastd_sockaddr_t remote;
	fastd_softc_t *sc;
	u_int32_t af;

	sc = ifp->if_softc;

	FASTD_RLOCK(sc, &tracker);
	if ((ifp->if_drv_flags & IFF_DRV_RUNNING) == 0) {
		FASTD_RUNLOCK(sc, &tracker);
		m_freem(m);
		return ENETDOWN;
	}

	/* BPF writes need to be handled specially. */
	if (dst->sa_family == AF_UNSPEC)
		bcopy(dst->sa_data, &af, sizeof(af));
	else
		af = dst->sa_family;

	fastd_sockaddr_copy(&remote, &sc->remote);

	FASTD_ACQUIRE(sc);
	FASTD_RUNLOCK(sc, &tracker);

	// Pass to Berkeley Packet Filter
	BPF_MTAP2(ifp, &af, sizeof(af), m);

	error = fastd_encap(sc, &remote, m);
	fastd_release(sc);

	return (error);
}

static void
fastd_ifstart(struct ifnet *ifp __unused)
{
}


static void
fastd_iface_load()
{
	int i;

	for (i = 0; i < FASTD_HASH_SIZE; i++) {
		LIST_INIT(&fastd_peers[i]);
	}

	rm_init(&fastd_lock, "fastd_lock");
	fastd_cloner = if_clone_simple(fastdname, fastd_clone_create, fastd_clone_destroy, 0);
}

static void
fastd_iface_unload()
{
	int i;
	fastd_softc_t *sc;

	if_clone_detach(fastd_cloner);

	// teardown interfaces
	rm_wlock(&fastd_lock);
	LIST_FOREACH(sc, &fastd_ifaces_head, fastd_ifaces) {
		fastd_teardown(sc);
	}
	rm_wunlock(&fastd_lock);

	// destroy interfaces
	while ((sc = LIST_FIRST(&fastd_ifaces_head)) != NULL) {
		LIST_REMOVE(sc, fastd_ifaces);
		fastd_destroy(sc);
	}

	for (i = 0; i < FASTD_HASH_SIZE; i++) {
		KASSERT(LIST_EMPTY(&fastd_peers[i]), "fastd: list not empty");
	}
}

static int
fastd_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
	fastd_softc_t *sc;
	struct iffastdcfg cfg;
	struct ifnet *ifp;
	fastd_sockaddr_t sa;
	int error = 0;

	// allocs
	ifp = if_alloc(IFT_PPP);
	if (!ifp)
		return ENOSPC;
	sc = malloc(sizeof(*sc), M_FASTD, M_WAITOK | M_ZERO);

	// inits
	sc->ifp = ifp;
	if_initname(ifp, fastdname, unit);
	rm_init(&sc->lock, "fastdrm");

	rm_wlock(&fastd_lock);

	// params
	if (params) {
		IFP_DEBUG(ifp, "params found");

		error = copyin(params, &cfg, sizeof(cfg));
		if (error)
			goto fail;

		inet_to_sock(&sa, &cfg.remote);

		if (fastd_lookup_peer(&sa)){
			IFP_DEBUG(sc->ifp, "address taken");
			error = EBUSY;
			goto fail;
		}

		error = fastd_add_peer(sc, &sa, cfg.pubkey);
		if (error)
			goto fail;
	}

	ifp->if_softc = sc;
	ifp->if_ioctl = fastd_ifioctl;
	ifp->if_output = fastd_output;
	ifp->if_start = fastd_ifstart;
	ifp->if_mtu = FASTD_MTU;
	ifp->if_flags = IFF_POINTOPOINT | IFF_MULTICAST;
	ifp->if_capabilities |= IFCAP_LINKSTATE;
	ifp->if_capenable |= IFCAP_LINKSTATE;

	IFP_DEBUG(ifp, "attach");
	if_attach(ifp);
	bpfattach(ifp, DLT_NULL, sizeof(u_int32_t));

	LIST_INSERT_HEAD(&fastd_ifaces_head, sc, fastd_ifaces);

	goto unlock;

fail:
	rm_destroy(&sc->lock);
	if_free(sc->ifp);
	free(sc, M_FASTD);

unlock:
	rm_wunlock(&fastd_lock);

	return (error);
}


static void
fastd_clone_destroy(struct ifnet *ifp)
{
	IFP_DEBUG(ifp, "called");

	fastd_softc_t *sc = ifp->if_softc;

	rm_wlock(&fastd_lock);
	fastd_teardown(sc);
	LIST_REMOVE(sc, fastd_ifaces);
	rm_wunlock(&fastd_lock);

	fastd_destroy(sc);
}

static void
fastd_destroy(fastd_softc_t *sc)
{
	IFP_DEBUG(sc->ifp, "called");

	// teardown must have already called before
	MPASS(sc->flags & FASTD_FLAG_TEARDOWN);

	// Wait for reference counter to become zero
	FASTD_WLOCK(sc);
	while (sc->refcnt != 0) {
		rm_sleep(sc, &sc->lock, 0, "fastd_destroy", hz);
	}
	FASTD_WUNLOCK(sc);

	IFP_DEBUG(sc->ifp, "detach");
	bpfdetach(sc->ifp);
	if_detach(sc->ifp);
	if_free(sc->ifp);
	rm_destroy(&sc->lock);
	free(sc, M_FASTD);
}

static void
fastd_teardown(fastd_softc_t *sc) {
	struct ifnet *ifp = sc->ifp;

	rm_assert(&fastd_lock, RA_WLOCKED);
	sc->flags |= FASTD_FLAG_TEARDOWN;

	if (ifp->if_flags & IFF_UP) {
		rm_wunlock(&fastd_lock);
		if_down(ifp);
		rm_wlock(&fastd_lock);
	}

	if (ifp->if_drv_flags & IFF_DRV_RUNNING) {
		struct ifaddr *ifa;

		ifp->if_drv_flags &= ~IFF_DRV_RUNNING;
		rm_wunlock(&fastd_lock);

		CK_STAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			rtinit(ifa, (int)RTM_DELETE, 0);
		}
		if_purgeaddrs(ifp);
		rm_wlock(&fastd_lock);
	}

	fastd_remove_peer(sc);
}


static void
fastd_remove_peer(fastd_softc_t *sc)
{
	fastd_softc_t *entry;
	// Remove from flows
	LIST_FOREACH(entry, &fastd_peers[FASTD_HASH(sc)], fastd_flow_entry) {
		if (fastd_sockaddr_equal(&entry->remote, &sc->remote)) {
			LIST_REMOVE(entry, fastd_flow_entry);
			break;
		}
	}

	// Remove from socket
	if (sc->socket != NULL) {
		LIST_REMOVE(sc, fastd_socket_entry);
		sc->socket = NULL;
	}
}

static fastd_softc_t*
fastd_lookup_peer(const fastd_sockaddr_t *addr)
{
	fastd_softc_t *entry;

	rm_assert(&fastd_lock, RA_LOCKED);
	LIST_FOREACH(entry, &fastd_peers[FASTD_HASH_ADDR(addr)], fastd_flow_entry) {
		if (fastd_sockaddr_equal(&entry->remote, addr))
			return entry;
	}

	return NULL;
}

static int
fastd_add_peer(fastd_softc_t *sc, fastd_sockaddr_t *sa, char pubkey[FASTD_PUBKEY_SIZE])
{
	fastd_socket_t *socket;
	rm_assert(&fastd_lock, RA_WLOCKED);

	if (sa->in4.sin_port == 0 || fastd_sockaddr_unspecified(sa))
		return EINVAL;

	// Find socket
	socket = fastd_find_socket_locked(sa);
	if (!socket) {
		IFP_DEBUG(sc->ifp, "unable to find socket");
		return EADDRNOTAVAIL;
	}

	// Set remote address
	fastd_sockaddr_copy(&sc->remote, sa);

	// Set public key
	if (pubkey){
		IFP_DEBUG(sc->ifp, "setting pubkey");
		memcpy(&sc->pubkey, pubkey, sizeof(sc->pubkey));
	}

	// Add to flows
	LIST_INSERT_HEAD(&fastd_peers[FASTD_HASH(sc)], sc, fastd_flow_entry);

	// Assign to new socket
	sc->socket = socket;
	LIST_INSERT_HEAD(&sc->socket->softc_head, sc, fastd_socket_entry);

	// Ready to deliver packets
	sc->ifp->if_drv_flags |= IFF_DRV_RUNNING;
	if_link_state_change(sc->ifp, LINK_STATE_UP);

	return 0;
}



static void
fastd_ifinit(struct ifnet *ifp)
{
	IFP_DEBUG(ifp, "initializing");

	rm_wlock(&fastd_lock);
	ifp->if_flags |= IFF_UP;
	rm_wunlock(&fastd_lock);
}




// ------------------------------------------------------------------
// Functions for control device
// ------------------------------------------------------------------




// Functions that are called on SIOCGDRVSPEC and SIOCSDRVSPEC
static const struct fastd_control fastd_control_table[] = {

	[FASTD_CMD_GET_REMOTE] =
			{   fastd_ctrl_get_remote, sizeof(struct iffastdcfg),
		FASTD_CTRL_FLAG_COPYOUT
			},

	[FASTD_CMD_SET_REMOTE] =
			{   fastd_ctrl_set_remote, sizeof(struct iffastdcfg),
		FASTD_CTRL_FLAG_COPYIN
			},

	[FASTD_CMD_GET_STATS] =
			{   fastd_ctrl_get_stats, sizeof(struct iffastdstats),
		FASTD_CTRL_FLAG_COPYOUT
			},
};

static const int fastd_control_table_size = nitems(fastd_control_table);



static int
fastd_ctrl_get_remote(fastd_softc_t *sc, void *arg)
{
	struct iffastdcfg *cfg;

	cfg = arg;
	bzero(cfg, sizeof(*cfg));

	memcpy(&cfg->pubkey, &sc->pubkey, sizeof(cfg->pubkey));

	if (FASTD_SOCKADDR_IS_IPV46(&sc->remote))
		sock_to_inet(&cfg->remote, &sc->remote);

	return (0);
}


static int
fastd_ctrl_set_remote(fastd_softc_t *sc, void *arg)
{
	struct iffastdcfg *cfg = arg;
	fastd_softc_t *other;
	fastd_sockaddr_t sa;
	int error = 0;
	inet_to_sock(&sa, &cfg->remote);

	rm_wlock(&fastd_lock);
	if (sc->flags & FASTD_FLAG_TEARDOWN) {
		error = EBUSY;
		goto out;
	}

	// address and port already taken?
	other = fastd_lookup_peer(&sa);
	if (other != NULL) {
		if (fastd_sockaddr_equal(&other->remote, &sa)){
			// peer has already the address
			IFP_DEBUG(sc->ifp, "address already configured");
		} else {
			error = EBUSY;
		}
		goto out;
	}

	// Reconfigure
	fastd_remove_peer(sc);
	error = fastd_add_peer(sc, &sa, cfg->pubkey);
out:
	rm_wunlock(&fastd_lock);
	return (error);
}

static int
fastd_ctrl_get_stats(fastd_softc_t *sc, void *arg)
{
	struct ifnet *ifp = sc->ifp;
	struct iffastdstats *stats = arg;

	stats->ipackets = ifp->if_get_counter(ifp, IFCOUNTER_IPACKETS);
	stats->opackets = ifp->if_get_counter(ifp, IFCOUNTER_OPACKETS);

	return (0);
}


static int
fastd_ioctl_drvspec(fastd_softc_t *sc, struct ifdrv *ifd, int get)
{
	const struct fastd_control *vc;
	struct iffastdcfg args;
	int out, error;


	if (ifd->ifd_cmd >= fastd_control_table_size){
		IFP_DEBUG(sc->ifp, "invalid command: %lu", ifd->ifd_cmd);
		return (EINVAL);
	}

	bzero(&args, sizeof(args));
	vc = &fastd_control_table[ifd->ifd_cmd];
	out = (vc->fastdc_flags & FASTD_CTRL_FLAG_COPYOUT) != 0;

	if ((get != 0 && out == 0) || (get == 0 && out != 0)){
		IFP_DEBUG(sc->ifp, "invalid flags");
		return (EINVAL);
	}

	if (ifd->ifd_len != vc->fastdc_argsize || ifd->ifd_len > sizeof(args)){
		IFP_DEBUG(sc->ifp, "invalid argsize given=%lu expected=%d, args=%lu", ifd->ifd_len, vc->fastdc_argsize, sizeof(args));
		return (EINVAL);
	}

	if (vc->fastdc_flags & FASTD_CTRL_FLAG_COPYIN) {
		error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
		if (error) {
			IFP_DEBUG(sc->ifp, "copyin failed");
			return (error);
		}
	}

	error = vc->fastdc_func(sc, &args);
	if (error)
		return (error);

	if (vc->fastdc_flags & FASTD_CTRL_FLAG_COPYOUT) {
		error = copyout(&args, ifd->ifd_data, ifd->ifd_len);
		if (error)
			return (error);
	}

	return (0);
}


static int
fastd_ifioctl(struct ifnet *ifp, u_long cmd, caddr_t data)
{
	fastd_softc_t *sc;
	struct ifdrv *ifd = (struct ifdrv *)data;
	struct ifreq *ifr = (struct ifreq *)data;
	struct ifstat *ifs;
	int error = 0;

	sc = ifp->if_softc;

	switch(cmd) {
	case SIOCGIFSTATUS:
		ifs = (struct ifstat *)data;
		char buf[INET6_ADDRSTRLEN];

		switch (sc->remote.sa.sa_family) {
		case AF_INET:
			snprintf(ifs->ascii, sizeof(ifs->ascii),
				"\tremote port=%d inet4=%s\n",
				ntohs(sc->remote.in4.sin_port),
				inet_ntop(AF_INET, &sc->remote.in4.sin_addr, buf, sizeof(buf))
			);
			break;
		case AF_INET6:
			snprintf(ifs->ascii, sizeof(ifs->ascii),
				"\tremote port=%d inet6=%s\n",
				ntohs(sc->remote.in6.sin6_port),
				inet_ntop(AF_INET6, &sc->remote.in6.sin6_addr, buf, sizeof(buf))
			);
			break;
		default:
			ifs->ascii[0] = '\0';
		}
		break;
	case SIOCSIFADDR:
		fastd_ifinit(ifp);
		IFP_DEBUG(ifp, "address set");
		/*
		 * Everything else is done at a higher level.
		 */
		break;
	case SIOCSIFMTU:
		// Set MTU
		ifp->if_mtu = ifr->ifr_mtu;
		break;
	case SIOCGDRVSPEC:
	case SIOCSDRVSPEC:
		DEBUGF("SIOCGDRVSPEC/SIOCSDRVSPEC ifname=%s cmd=%lx len=%lu\n", ifd->ifd_name, ifd->ifd_cmd, ifd->ifd_len);
		error = fastd_ioctl_drvspec(sc, ifd, cmd == SIOCGDRVSPEC);
		break;
	case SIOCSIFFLAGS:
		break;
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		break;
	default:
		error = EINVAL;
	}
	return (error);
}
