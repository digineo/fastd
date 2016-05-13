#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc.h>

#include "socket.h"

static struct socket *fastd_sock;

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
			return error;
		}
	}

	if (laddr->sa.sa_family == AF_INET) {
		uprintf("binding ipv4 socket, port=%u addr=%08X\n", laddr->in4.sin_port, laddr->in4.sin_addr.s_addr);
	} else if (laddr->sa.sa_family == AF_INET6) {
		uprintf("binding ipv6 socket\n");
	} else{
		uprintf("unknown family: %u\n", laddr->sa.sa_family);
	}
	error = sobind(fastd_sock, &laddr->sa, curthread);

	if (error) {
		uprintf("cannot bind socket: %d\n", error);
	}
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
