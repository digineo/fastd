#include <net/if.h>
#include <net/if_var.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet6/in6_var.h>

int set_fd(sa_family_t, int);
int get_ifindex(char*);
int remove_addr4(char*);
int remove_addr6(char*, struct sockaddr_storage*);
int add_addr4(char*, struct sockaddr_storage*, struct sockaddr_storage*);
int add_addr6(char*, struct sockaddr_storage*, struct sockaddr_storage*);
