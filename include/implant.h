#ifndef implant_H
#define implant_H

#include <stddef.h>

void implant_init_n_call(char *dest_ip);
int create_socket(void);
size_t invoke_command(unsigned char *data, unsigned char *output);
void interact(int sockfd, char *dest_ip);

#endif