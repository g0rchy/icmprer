#include <stdio.h>
#include <stdlib.h>
#include "../include/implant.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Specify the IP address to connect to as an argument\n");
        return 1;
    }
    
    implant_init_n_call(argv[1]);

    return 0;
}