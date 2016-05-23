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

#include "fastd.h"
#include "iface.h"


struct fastd_softc {
	// lists are protected by global fastd_lock
	TAILQ_ENTRY(fastd_softc) fastd_list; // list of all interfaces
	LIST_ENTRY(fastd_softc) fastd_flow_entry; // entry in flow table

	struct ifnet *fastd_ifp;	/* the interface */
	union fastd_sockaddr remote;	/* remote ip address and port */
};


#define	satoconstsin(sa)	((const struct sockaddr_in *)(sa))
#define	satoconstsin6(sa)	((const struct sockaddr_in6 *)(sa))

#define FASTD_HASH_SHIFT	6
#define FASTD_HASH_SIZE		(1 << FASTD_HASH_SHIFT)
#define FASTD_HASH(_sc)	((_sc)->remote.in4.sin_port % FASTD_HASH_SIZE)

// Mapping from sources addresses to interfaces
LIST_HEAD(fastd_softc_head, fastd_softc);
struct fastd_softc_head fastd_peers[FASTD_HASH_SIZE];

static struct rmlock fastd_lock;
static const char fastdname[] = "fastd";

// List of all interfaces
static TAILQ_HEAD(,fastd_softc)	fastdhead = TAILQ_HEAD_INITIALIZER(fastdhead);

static int	fastd_clone_create(struct if_clone *, int, caddr_t);
static void	fastd_clone_destroy(struct ifnet *);
static void	fastd_destroy(struct fastd_softc *sc);
static int	fastd_ifioctl(struct ifnet *, u_long, caddr_t);
static int	fastd_ioctl_drvspec(struct fastd_softc *, struct ifdrv *, int);
static struct if_clone *fastd_cloner;

static void	fastd_add_peer(struct fastd_softc *);
static void	fastd_remove_peer(struct fastd_softc *);

static int	fastd_sockaddr_equal(const union fastd_sockaddr *, const union fastd_sockaddr *);

static int	fastd_ctrl_get_config(struct fastd_softc *, void *);
static int	fastd_ctrl_set_remote(struct fastd_softc *, void *);

struct fastd_control {
	int	(*fastdc_func)(struct fastd_softc *, void *);
	int	fastdc_argsize;
	int	fastdc_flags;
#define FASTD_CTRL_FLAG_COPYIN	0x01
#define FASTD_CTRL_FLAG_COPYOUT	0x02
};

static const struct fastd_control fastd_control_table[] = {
	[FASTD_CMD_GET_CONFIG] =
	    {	fastd_ctrl_get_config, sizeof(struct iffastdcfg),
		FASTD_CTRL_FLAG_COPYOUT
	    },

	[FASTD_CMD_SET_REMOTE] =
	    {   fastd_ctrl_set_remote, sizeof(struct iffastdcfg),
		FASTD_CTRL_FLAG_COPYIN
	    },
};

static const int fastd_control_table_size = nitems(fastd_control_table);



void
fastd_iface_load()
{
	int i;

	for (i = 0; i < FASTD_HASH_SIZE; i++) {
		LIST_INIT(&fastd_peers[i]);
	}

	rm_init(&fastd_lock, "fastd_lock");
	fastd_cloner = if_clone_simple(fastdname, fastd_clone_create, fastd_clone_destroy, 0);
}

void
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

static void
fastd_add_peer(struct fastd_softc *sc)
{
	if (sc->remote.in4.sin_port > 0){
		// Add to flows
		LIST_INSERT_HEAD(&fastd_peers[FASTD_HASH(sc)], sc, fastd_flow_entry);
	}
}


static int
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
	int error = 0;

	rm_wlock(&fastd_lock);
	fastd_remove_peer(sc);
	inet_to_sock(&sc->remote, &cfg->remote);
	fastd_add_peer(sc);
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
