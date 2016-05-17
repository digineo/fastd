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

static struct fastd_socket fastd_sock;
static void	fastd_rcv_udp_packet(struct mbuf *, int, struct inpcb *, const struct sockaddr *, void *);


int
fastd_create_socket(){
	int error;

	uprintf("create socket\n");
	error = socreate(PF_INET, &fastd_sock.sock, SOCK_DGRAM, IPPROTO_UDP, curthread->td_ucred, curthread);

	if (error) {
		uprintf("cannot create socket: %d\n", error);
	}
	return (error);
}

int
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

void
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

int
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

