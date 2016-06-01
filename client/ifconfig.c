#include <string.h>
#include <net/if.h>
#include <net/if_var.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

static int ioctl_fd4 = 0;
static int ioctl_fd6 = 0;

int
set_fd(sa_family_t af, int fd){
	switch(af){
	case AF_INET:
		ioctl_fd4 = fd;
		break;
	case AF_INET6:
		ioctl_fd6 = fd;
		break;
	default:
		return 1;
	}
	return 0;
}

static inline void
mask32(struct sockaddr_in *sa){
	sa->sin_len    = sizeof(struct sockaddr_in6);
	sa->sin_family = AF_INET;
	memset(&sa->sin_addr, '\xff', sizeof(struct in_addr));
}

static inline void
mask128(struct sockaddr_in6 *sa){
	sa->sin6_len    = sizeof(struct sockaddr_in6);
	sa->sin6_family = AF_INET6;
	memset(&sa->sin6_addr, '\xff', sizeof(struct in6_addr));
}

int
remove_alias4(char* ifname)
{
	struct ifreq req;
	bzero(&req, sizeof(req));
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));

	return ioctl(ioctl_fd4, SIOCDIFADDR, &req);
}

int
remove_alias6(char* ifname, struct sockaddr_storage *addr)
{
	struct in6_ifreq req;
	bzero(&req, sizeof(req));
	strncpy(req.ifr_name, ifname, sizeof(req.ifr_name));
	memcpy(&req.ifr_addr, addr, sizeof(struct sockaddr_in6));

	return ioctl(ioctl_fd6, SIOCDIFADDR_IN6, &req);
}

int
add_alias4(char* ifname, struct sockaddr_storage *addr, struct sockaddr_storage *dstaddr)
{
	struct ifaliasreq req;
	bzero(&req, sizeof(req));

	strncpy(req.ifra_name,      ifname,  sizeof(req.ifra_name));
	memcpy(&req.ifra_addr,      addr,    sizeof(struct sockaddr));
	memcpy(&req.ifra_broadaddr, dstaddr, sizeof(struct sockaddr));
	mask32((struct sockaddr_in *)&req.ifra_mask);

	return ioctl(ioctl_fd4, SIOCAIFADDR, &req);
}

int
add_alias6(char* ifname, struct sockaddr_storage *addr, struct sockaddr_storage *dstaddr)
{
	struct in6_aliasreq req;
	bzero(&req, sizeof(req));

	strncpy(req.ifra_name,    ifname,  sizeof(req.ifra_name));
	memcpy(&req.ifra_addr,    addr,    sizeof(struct sockaddr_in6));
	memcpy(&req.ifra_dstaddr, dstaddr, sizeof(struct sockaddr_in6));
	mask128(&req.ifra_prefixmask);

	req.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
	req.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

	return ioctl(ioctl_fd6, SIOCAIFADDR_IN6, &req);
}
