#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_var.h>
#include <netinet6/ip6_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>

// ringbuffer
#include <sys/param.h>
#include <sys/buf_ring.h>

#include "socket.h"

static struct socket *fastd_sock;
static void	fastd_rcv_udp_packet(struct mbuf *, int, struct inpcb *,
		    const struct sockaddr *, void *);

int
fastd_create_socket(){
	int error;

	uprintf("create socket\n");
	error = socreate(PF_INET, &fastd_sock, SOCK_DGRAM, IPPROTO_UDP, curthread->td_ucred, curthread);

	if (error) {
		uprintf("cannot create socket: %d\n", error);
	}
	return (error);
}

int
fastd_bind_socket(union fastd_sockaddr *laddr){
	int error;

	if (fastd_sock == NULL){
		error = fastd_create_socket();
		if (error) {
			goto out;
		}
	}

	if (laddr->sa.sa_family == AF_INET) {
		uprintf("binding ipv4 socket, port=%u addr=%08X\n", ntohs(laddr->in4.sin_port), laddr->in4.sin_addr.s_addr);
	} else if (laddr->sa.sa_family == AF_INET6) {
		uprintf("binding ipv6 socket\n");
	} else {
		uprintf("unknown family: %u\n", laddr->sa.sa_family);
	}
	error = sobind(fastd_sock, &laddr->sa, curthread);

	if (error == EADDRINUSE){
		uprintf("address in use\n");
		goto out;
	}
	if (error) {
		goto out;
	}

	error = udp_set_kernel_tunneling(fastd_sock, fastd_rcv_udp_packet, NULL);
	if (error) {
		uprintf("cannot set tunneling function: %d\n", error);
	}else{
		uprintf("tunneling function set\n");
	}

out:
	return (error);
}

void
fastd_destroy_socket(){
	if (fastd_sock != NULL) {
		uprintf("destroy socket\n");
		soclose(fastd_sock);
		fastd_sock = NULL;
	}
}

static void
fastd_rcv_udp_packet(struct mbuf *m, int offset, struct inpcb *inpcb,
    const struct sockaddr *sa, void *xfso)
{

	// Ensure packet header exists
	M_ASSERTPKTHDR(m);

	struct fastd_message *fastd_msg;
	struct fastd_header *fdh, fastd_hdr;
	offset += sizeof(struct udphdr);

	if (sa->sa_family == AF_INET){
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;
		printf("fastd: received UDP packet port=%u offset=%d hdrlen=%d \n", ntohs(sin->sin_port), offset, m->m_pkthdr.len);
	}

	if (m->m_pkthdr.len < offset + sizeof(struct fastd_header))
		goto out;

	if (__predict_false(m->m_len < offset + sizeof(struct fastd_header))) {
		// message is too short
		m_copydata(m, offset, sizeof(struct fastd_header), (caddr_t) &fastd_hdr);
		fdh = &fastd_hdr;
	} else
		fdh = mtodo(m, offset);

	switch (fdh->fdh_type){
	case FASTD_HDR_CTRL:
		fastd_msg = malloc(sizeof(struct fastd_message), M_FASTD, M_WAITOK);
		// Copy address
		memcpy((void *)&fastd_msg->sockaddr, sa, sizeof(union fastd_sockaddr));
		// Copy fastd packet
		m_copydata(m, offset, min(sizeof(struct fastd_packet), m->m_len - offset), (caddr_t) &fastd_msg->packet);
		// Store into ringbuffer to character device
		buf_ring_enqueue(fastd_msgbuf, fastd_msg);
		break;
	case FASTD_HDR_DATA:
		// TODO forward to network interface
		break;
	default:
		printf("invalid fastd-packet type=%02X\n", fdh->fdh_type);
	}

out:
	if (m != NULL)
		m_freem(m);
}
