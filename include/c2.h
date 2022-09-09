#ifndef C2_H
#define C2_H

#include <netinet/ip_icmp.h>
#define COMMAND_SIZE 1024
#define MAX_DATA_SIZE 1472

void c2_init_n_call(char *interface_to_bind);
int create_socket(char *inteface_to_bind);
int read_from_socket(int sockfd, char *buffer,int size);
void interact(int sockfd);
void print_connection_succeed(char *src_ip);
char *get_command(void);
int check_magic_byte(struct icmphdr *icmp);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
char *parse_data_section(char *packet);
void prep_icmp_headers(struct icmphdr *icmp, char *data, uint16_t checksum);
void append_to_data_section(struct icmphdr *icmp, char *data, char *input);

#endif