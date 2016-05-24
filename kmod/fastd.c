#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>
#include <sys/socketvar.h>
#include <sys/param.h>
#include <sys/buf_ring.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/systm.h>
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
#include <net/route.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

#include "fastd.h"


/* Maximum transmit packet size (default) */
#define	FASTDMTU		1406

#define FASTD_SOCKADDR_IS_IPV4(_vxsin)	((_vxsin)->sa.sa_family == AF_INET)
#define FASTD_SOCKADDR_IS_IPV6(_vxsin)	((_vxsin)->sa.sa_family == AF_INET6)
#define FASTD_SOCKADDR_IS_IPV46(_vxsin) \
    (FASTD_SOCKADDR_IS_IPV4(_vxsin) || FASTD_SOCKADDR_IS_IPV6(_vxsin))

#define FASTD_HASH_SHIFT  6
#define FASTD_HASH_SIZE   (1 << FASTD_HASH_SHIFT)
#define FASTD_HASH_ADDR(_sa)  ((_sa)->in4.sin_port % FASTD_HASH_SIZE)
#define FASTD_HASH(_sc)   ((_sc)->remote.in4.sin_port % FASTD_HASH_SIZE)

// SIOCGDRVSPEC/SIOCSDRVSPEC commands on fastd interface
#define FASTD_CMD_GET_CONFIG	0
#define FASTD_CMD_SET_REMOTE	1

#define satoconstsin(sa)  ((const struct sockaddr_in *)(sa))
#define satoconstsin6(sa) ((const struct sockaddr_in6 *)(sa))

struct iffastdcfg {
	struct fastd_inaddr	remote;
};

static void fastd_iface_load(void);
static void fastd_iface_unload(void);


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
static struct buf_ring *fastd_msgbuf;
static struct mtx       fastd_msgmtx;

static int fastd_create_socket(void);
static int fastd_bind_socket(union fastd_sockaddr* laddr);
static void fastd_destroy_socket(void);
static int fastd_send_packet(struct uio *uio);




struct fastd_softc {
  // lists are protected by global fastd_lock
  TAILQ_ENTRY(fastd_softc) fastd_list; // list of all interfaces
  LIST_ENTRY(fastd_softc) fastd_flow_entry; // entry in flow table

  struct ifnet *fastd_ifp;  /* the interface */
  union fastd_sockaddr remote;  /* remote ip address and port */
};



// Mapping from sources addresses to interfaces
LIST_HEAD(fastd_softc_head, fastd_softc);
struct fastd_softc_head fastd_peers[FASTD_HASH_SIZE];

static struct rmlock fastd_lock;
static const char fastdname[] = "fastd";

// List of all interfaces
static TAILQ_HEAD(,fastd_softc) fastdhead = TAILQ_HEAD_INITIALIZER(fastdhead);

static int  fastd_clone_create(struct if_clone *, int, caddr_t);
static void fastd_clone_destroy(struct ifnet *);
static void fastd_destroy(struct fastd_softc *sc);
static int  fastd_ifioctl(struct ifnet *, u_long, caddr_t);
static int  fastd_ioctl_drvspec(struct fastd_softc *, struct ifdrv *, int);
static struct if_clone *fastd_cloner;

static void fastd_add_peer(struct fastd_softc *);
static void fastd_remove_peer(struct fastd_softc *);
static struct fastd_softc* fastd_lookup_peer(const union fastd_sockaddr *);

static void fastd_sockaddr_copy(union fastd_sockaddr *, const union fastd_sockaddr *);
static int  fastd_sockaddr_equal(const union fastd_sockaddr *, const union fastd_sockaddr *);

static int  fastd_ctrl_get_config(struct fastd_softc *, void *);
static int  fastd_ctrl_set_remote(struct fastd_softc *, void *);

struct fastd_control {
  int (*fastdc_func)(struct fastd_softc *, void *);
  int fastdc_argsize;
  int fastdc_flags;
#define FASTD_CTRL_FLAG_COPYIN  0x01
#define FASTD_CTRL_FLAG_COPYOUT 0x02
};



// ------------------------------------------------------------------
// Functions for control device
// ------------------------------------------------------------------


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


DEV_MODULE(fastd, fastd_modevent, NULL);


// ------------------------------------------------------------------
// Socket helper functions
// ------------------------------------------------------------------


static inline int
isIPv4(const struct fastd_inaddr *inaddr){
  char *buf = (char *) inaddr;
  return (
       (char)0x00 == (buf[0] | buf[1] | buf[2] | buf[3] | buf[4] | buf[5]| buf[6] | buf[7] | buf[8] | buf[9])
    && (char)0xff == (buf[10] & buf[11])
  );
}

// Copies a fastd_inaddr into a fixed length fastd_sockaddr
static inline void
sock_to_inet(struct fastd_inaddr *dst, const union fastd_sockaddr *src){
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



// copy fastd_sockaddr to fastd_sockaddr
static inline void
fastd_sockaddr_copy(union fastd_sockaddr *dst, const union fastd_sockaddr *src)
{
  bzero(dst, sizeof(*dst));

  switch (src->sa.sa_family) {
  case AF_INET:
    dst->in4 = *satoconstsin(src);
    dst->in4.sin_len = sizeof(struct sockaddr_in);
    break;
  case AF_INET6:
    dst->in6 = *satoconstsin6(src);
    dst->in6.sin6_len = sizeof(struct sockaddr_in6);
    break;
  }
}



// compares fastd_sockaddr with another fastd_sockaddr
static inline int
fastd_sockaddr_equal(const union fastd_sockaddr *a, const union fastd_sockaddr *b)
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



// ------------------------------------------------------------------
// Network functions
// ------------------------------------------------------------------




static struct fastd_socket fastd_sock;
static void fastd_rcv_udp_packet(struct mbuf *, int, struct inpcb *, const struct sockaddr *, void *);


static int
fastd_create_socket(){
  int error;

  uprintf("create socket\n");
  error = socreate(PF_INET, &fastd_sock.sock, SOCK_DGRAM, IPPROTO_UDP, curthread->td_ucred, curthread);

  if (error) {
    uprintf("cannot create socket: %d\n", error);
  }
  return (error);
}

static int
fastd_bind_socket(union fastd_sockaddr *laddr){
  int error;

  if (fastd_sock.sock == NULL){
    error = fastd_create_socket();
    if (error) {
      goto out;
    }
  }

  // Copy listen address
  fastd_sock.laddr = *laddr;

  if (laddr->sa.sa_family == AF_INET) {
    uprintf("binding ipv4 socket, port=%u addr=%08X\n", ntohs(laddr->in4.sin_port), laddr->in4.sin_addr.s_addr);
  } else if (laddr->sa.sa_family == AF_INET6) {
    uprintf("binding ipv6 socket\n");
  } else {
    uprintf("unknown family: %u\n", laddr->sa.sa_family);
  }
  error = sobind(fastd_sock.sock, &laddr->sa, curthread);

  if (error == EADDRINUSE){
    uprintf("address in use\n");
    goto out;
  }
  if (error) {
    goto out;
  }

  error = udp_set_kernel_tunneling(fastd_sock.sock, fastd_rcv_udp_packet, &fastd_sock);
  if (error) {
    uprintf("cannot set tunneling function: %d\n", error);
  }else{
    uprintf("tunneling function set\n");
  }

out:
  return (error);
}


static void
fastd_destroy_socket(){
  if (fastd_sock.sock != NULL) {
    uprintf("destroy socket\n");
    soclose(fastd_sock.sock);
    fastd_sock.sock = NULL;
  }
}


static void
fastd_rcv_udp_packet(struct mbuf *m, int offset, struct inpcb *inpcb,
    const struct sockaddr *sa_src, void *xfso)
{
  struct fastd_message *fastd_msg;
  char msg_type;
  u_int datalen;
  struct fastd_socket *fso;

  // Ensure packet header exists
  M_ASSERTPKTHDR(m);

  fso = xfso;
  offset += sizeof(struct udphdr);

  // drop UDP packets with less than 4 bytes payload
  if (m->m_pkthdr.len < offset + 4)
    goto out;

  m_copydata(m, offset, 1, (caddr_t) &msg_type);

  switch (msg_type){
  case FASTD_HDR_CTRL:
    datalen   = m->m_len - offset;
    fastd_msg = malloc(sizeof(struct fastd_message) + datalen, M_FASTD, M_WAITOK);
    fastd_msg->datalen = datalen;

    // Copy addresses
    sock_to_inet(&fastd_msg->src, (union fastd_sockaddr *)sa_src);
    sock_to_inet(&fastd_msg->dst, &fso->laddr);

    // Copy fastd packet
    m_copydata(m, offset, datalen, (caddr_t) &fastd_msg->data);

    // Store into ringbuffer to character device
    buf_ring_enqueue(fastd_msgbuf, fastd_msg);
    break;
  case FASTD_HDR_DATA:
    // TODO forward to network interface
    break;
  default:
    printf("invalid fastd-packet type=%02X\n", msg_type);
  }

out:
  if (m != NULL)
    m_freem(m);
}

// Send outgoing control packet via UDP
static int
fastd_send_packet(struct uio *uio) {
  int error;
  size_t datalen, addrlen;
  struct fastd_message msg;
  struct mbuf *m = NULL;
  struct sockaddr dst_addr;

  if (fastd_sock.sock == NULL) {
    return EIO;
  }

  addrlen = 2 * sizeof(struct fastd_inaddr);
  datalen = uio->uio_iov->iov_len - addrlen;

  // Copy addresses from user memory
  error = uiomove((char *)&msg + sizeof(uint16_t), addrlen, uio);
  if (error != 0){
    goto out;
  }

  // Build destination address
  inet_to_sock((union fastd_sockaddr *)&dst_addr, &msg.dst);

  // Allocate space for packet
  m = m_getm(NULL, datalen, M_WAITOK, MT_DATA);

  // Set mbuf current data length
  m->m_len = m->m_pkthdr.len = datalen;

  // Copy payload from user memory
  error = uiomove(m->m_data, datalen, uio);
  if (error != 0){
    goto fail;
  }

  // Send packet
  error = sosend(fastd_sock.sock, &dst_addr, NULL, m, NULL, 0, uio->uio_td);
  if (error != 0){
    goto fail;
  }

  goto out;
fail:
  m_free(m);
out:
  return (error);
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
  struct fastd_softc *sc;

  if_clone_detach(fastd_cloner);

  rm_wlock(&fastd_lock);
  while ((sc = TAILQ_FIRST(&fastdhead)) != NULL) {
    fastd_destroy(sc);
  }
  rm_wunlock(&fastd_lock);
  rm_destroy(&fastd_lock);

  for (i = 0; i < FASTD_HASH_SIZE; i++) {
    KASSERT(LIST_EMPTY(&fastd_peers[i]), "fastd: list not empty");
  }
}

static int
fastd_clone_create(struct if_clone *ifc, int unit, caddr_t params)
{
  struct fastd_softc *sc;
  struct ifnet *ifp;
  int error;

  sc = malloc(sizeof(*sc), M_FASTD, M_WAITOK | M_ZERO);

  if (params != 0) {
    // TODO
  }

  ifp = if_alloc(IFT_PPP);
  if (ifp == NULL) {
    error = ENOSPC;
    goto fail;
  }

  sc->fastd_ifp = ifp;

  if_initname(ifp, fastdname, unit);
  ifp->if_softc = sc;
  ifp->if_ioctl = fastd_ifioctl;
  ifp->if_mtu = FASTDMTU;
  ifp->if_flags = IFF_POINTOPOINT | IFF_MULTICAST;
  ifp->if_capabilities |= IFCAP_LINKSTATE;
  ifp->if_capenable |= IFCAP_LINKSTATE;

  if_attach(ifp);

  rm_wlock(&fastd_lock);
  TAILQ_INSERT_TAIL(&fastdhead, sc, fastd_list);
  rm_wunlock(&fastd_lock);

  return (0);

fail:
  free(sc, M_FASTD);
  return (error);
}


static void
fastd_clone_destroy(struct ifnet *ifp)
{
  struct fastd_softc *sc;
  sc = ifp->if_softc;

  rm_wlock(&fastd_lock);
  fastd_remove_peer(sc);
  fastd_destroy(sc);
  rm_wunlock(&fastd_lock);
}

// fastd_lock must be locked before
static void
fastd_destroy(struct fastd_softc *sc)
{
  TAILQ_REMOVE(&fastdhead, sc, fastd_list);

  if_detach(sc->fastd_ifp);
  if_free(sc->fastd_ifp);
  free(sc, M_FASTD);
}

static void
fastd_remove_peer(struct fastd_softc *sc)
{
  struct fastd_softc *entry;
  // Remove from flows
  LIST_FOREACH(entry, &fastd_peers[FASTD_HASH(sc)], fastd_flow_entry) {
    if (fastd_sockaddr_equal(&entry->remote, &sc->remote)) {
      LIST_REMOVE(entry, fastd_flow_entry);
      break;
    }
  }
}

static struct fastd_softc*
fastd_lookup_peer(const union fastd_sockaddr *addr)
{
  struct fastd_softc *entry;
  LIST_FOREACH(entry, &fastd_peers[FASTD_HASH_ADDR(addr)], fastd_flow_entry) {
    if (fastd_sockaddr_equal(&entry->remote, addr)) {
      return entry;
    }
  }

  return NULL;
}

static void
fastd_add_peer(struct fastd_softc *sc)
{
  if (sc->remote.in4.sin_port > 0){
    // Add to flows
    LIST_INSERT_HEAD(&fastd_peers[FASTD_HASH(sc)], sc, fastd_flow_entry);
  }
}




// ------------------------------------------------------------------
// Functions for control device
// ------------------------------------------------------------------




// Functions that are called on SIOCGDRVSPEC and SIOCSDRVSPEC
static const struct fastd_control fastd_control_table[] = {
  [FASTD_CMD_GET_CONFIG] =
      { fastd_ctrl_get_config, sizeof(struct iffastdcfg),
    FASTD_CTRL_FLAG_COPYOUT
      },

  [FASTD_CMD_SET_REMOTE] =
      {   fastd_ctrl_set_remote, sizeof(struct iffastdcfg),
    FASTD_CTRL_FLAG_COPYIN
      },
};

static const int fastd_control_table_size = nitems(fastd_control_table);



static int
fastd_ctrl_get_config(struct fastd_softc *sc, void *arg)
{
  struct iffastdcfg *cfg;

  printf("fastd_ctrl_get_config()\n");

  cfg = arg;
  bzero(cfg, sizeof(*cfg));

  memcpy(&cfg->remote, &sc->remote, sizeof(union fastd_sockaddr));

  return (0);
}


static int
fastd_ctrl_set_remote(struct fastd_softc *sc, void *arg)
{
  struct iffastdcfg *cfg = arg;
  struct fastd_softc *other;
  union fastd_sockaddr sa;
  int error = 0;
  inet_to_sock(&sa, &cfg->remote);

  rm_wlock(&fastd_lock);

  // address and port already taken?
  other = fastd_lookup_peer(&sa);
  if (other != NULL && other != sc) {
    error = EADDRNOTAVAIL;
    goto out;
  }

  // reconfigure
  fastd_remove_peer(sc);
  fastd_sockaddr_copy(&sc->remote, &sa);
  fastd_add_peer(sc);
out:
  rm_wunlock(&fastd_lock);
  return (error);
}


static int
fastd_ioctl_drvspec(struct fastd_softc *sc, struct ifdrv *ifd, int get)
{
  const struct fastd_control *vc;
  struct iffastdcfg args;
  int out, error;


  if (ifd->ifd_cmd >= fastd_control_table_size){
    printf("fastd_ioctl_drvspec() invalid command\n");
    return (EINVAL);
  }

  bzero(&args, sizeof(args));
  vc = &fastd_control_table[ifd->ifd_cmd];
  out = (vc->fastdc_flags & FASTD_CTRL_FLAG_COPYOUT) != 0;

  if ((get != 0 && out == 0) || (get == 0 && out != 0)){
    printf("fastd_ioctl_drvspec() invalid flags\n");
    return (EINVAL);
  }

  if (ifd->ifd_len != vc->fastdc_argsize ||
      ifd->ifd_len > sizeof(args)){
    printf("fastd_ioctl_drvspec() invalid argsize given=%lu expected=%d, args=%lu\n", ifd->ifd_len, vc->fastdc_argsize, sizeof(args));
    return (EINVAL);
  }

  if (vc->fastdc_flags & FASTD_CTRL_FLAG_COPYIN) {
    error = copyin(ifd->ifd_data, &args, ifd->ifd_len);
    if (error){
      printf("fastd_ioctl_drvspec() copyin failed\n");
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
  struct fastd_softc *sc;
  struct ifdrv *ifd = (struct ifdrv *)data;
  struct ifreq *ifr = (struct ifreq *)data;
  struct ifstat *ifs;
  int error = 0;

  sc = ifp->if_softc;

  switch(cmd) {
  case SIOCGIFSTATUS:
    ifs = (struct ifstat *)data;
    char ip6buf[INET6_ADDRSTRLEN];
    switch (sc->remote.sa.sa_family) {
    case AF_INET:
      sprintf(ifs->ascii + strlen(ifs->ascii),
            "\tremote port=%d inet4=%s\n", sc->remote.in4.sin_port, inet_ntoa(sc->remote.in4.sin_addr));
      break;
    case AF_INET6:
      sprintf(ifs->ascii + strlen(ifs->ascii),
            "\tremote port=%d inet6=%s\n", sc->remote.in6.sin6_port, ip6_sprintf(ip6buf, &sc->remote.in6.sin6_addr));
      break;
    }
    break;
  case SIOCSIFADDR:
  case SIOCAIFADDR:
    ifp->if_flags |= IFF_UP;
    ifp->if_drv_flags |= IFF_DRV_RUNNING;
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
    printf("SIOCGDRVSPEC/SIOCSDRVSPEC ifname=%s cmd=%lx len=%lu\n", ifd->ifd_name, ifd->ifd_cmd, ifd->ifd_len);
    error = fastd_ioctl_drvspec(sc, ifd, cmd == SIOCGDRVSPEC);
    break;
  case SIOCSIFFLAGS:
    break;
  case SIOCADDMULTI:
  case SIOCDELMULTI:
    error = EAFNOSUPPORT;
    break;
  default:
    printf("invalid cmd: %lx != %lx\n", cmd, SIOCSIFADDR);
    error = EINVAL;
  }
  return (error);
}
