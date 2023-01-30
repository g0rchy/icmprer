#include <stdio.h>
#include <getopt.h>

#include "../include/c2.h"

void print_usage(char *binpath) {
    fprintf(stderr, "Usage: %s -i [INTERFACE]\n\n  -i, --interface\tinterface to listen on\n  -h, --help\t\tdisplay help menu\n", binpath);
}

int main(int argc, char **argv) {
    int opt, do_parse_args = 1;
    const char* short_opts = "hi:";
    const struct option large_opts[] = {
        {"help", 0, NULL, 'h'},
        {"interface", 1, NULL, 'i'},
        {NULL, 0 , NULL, 0} // end of array
    };

    if (argc < 2) {
        puts("[!] No interface specified, listenning on all interfaces...");
        c2_init_n_call(NULL);
        do_parse_args = 0;
    }

    while (do_parse_args && (opt = getopt_long(argc, argv, short_opts, large_opts, NULL)) != -1) {
        switch (opt) {
            case 'i':
                c2_init_n_call(optarg);
                break;
            case '?': // invalid option, proceed to print the usage menu
            case 'h':
                print_usage(argv[0]);
                break;
            default: // what the hell you passed in?
                return 1;
       }
    }
    return 0;
}