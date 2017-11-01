#ifndef _IFCONFIG_H
#define _IFCONFIG_H

#include <net/if.h>
#include <net/if_var.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>

int set_fd(sa_family_t);
int if_clone(char*, void*);
int if_destroy(char*);
int get_descr(char*, char*, size_t);
int set_descr(char*, char*);
int get_mtu(char*, int*);
int set_mtu(char*, int);
int remove_addr4(char*);
int remove_addr6(char*, struct sockaddr_in6*);
int set_addr4(char*, struct sockaddr_in*, struct sockaddr_in*);
int add_addr4_ptp(char*, struct sockaddr_in*, struct sockaddr_in*);
int add_addr6_ptp(char*, struct sockaddr_in6*, struct sockaddr_in6*);
int add_addr6(char*, struct sockaddr_in6*, uint8_t);
int get_drv_spec(char*, unsigned long, void *, size_t);
int set_drv_spec(char*, unsigned long, void *, size_t);

#endif /* _IFCONFIG_H */
