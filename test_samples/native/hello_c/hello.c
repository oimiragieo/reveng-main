#include <stdio.h>
#include <string.h>

static void print_usage(FILE *stream)
{
    fputs("Usage: hello_c [--help|--version]\n", stream);
    fputs("  --help     Show this help message\n", stream);
    fputs("  --version  Print version and exit\n", stream);
}

int main(int argc, char **argv)
{
    if (argc == 1) {
        print_usage(stdout);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        print_usage(stdout);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        fputs("hello_c 1.0.0\n", stdout);
        return 0;
    }
    print_usage(stderr);
    return 2;
}
