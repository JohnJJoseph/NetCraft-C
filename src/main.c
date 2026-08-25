#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "syn_scanner.h"
#include "connect_scanner.h"
#include "packet_sniffer.h"
#include "arp_spoofer.h"

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s syn-scan <target> <port-range>     SYN scan (root)\n"
        "  %s connect-scan <target> <port-range> [threads]  Connect scan\n"
        "  %s sniffer <interface> <filter> [count]  Packet sniffer (root, needs libpcap)\n"
        "  %s arp-spoof <target-ip> <gateway-ip> <interface>  ARP spoof (root, educational)\n"
        "\n"
        "Port range format: start-end (e.g. 1-1024)\n",
        prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "syn-scan") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        int start = 0, end = 0;
        if (sscanf(argv[3], "%d-%d", &start, &end) != 2) {
            fprintf(stderr, "Invalid port range: %s\n", argv[3]);
            return 1;
        }
        return syn_scan(argv[2], start, end, 3000);
    }

    if (strcmp(argv[1], "connect-scan") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        int start = 0, end = 0;
        if (sscanf(argv[3], "%d-%d", &start, &end) != 2) {
            fprintf(stderr, "Invalid port range: %s\n", argv[3]);
            return 1;
        }
        int threads = argc > 4 ? atoi(argv[4]) : 10;
        return connect_scan(argv[2], start, end, threads);
    }

    if (strcmp(argv[1], "sniffer") == 0) {
        if (argc < 4) { usage(argv[0]); return 1; }
        int count = argc > 4 ? atoi(argv[4]) : -1;
        return run_sniffer(argv[2], argv[3], count);
    }

    if (strcmp(argv[1], "arp-spoof") == 0) {
        if (argc < 5) { usage(argv[0]); return 1; }
        return arp_spoof(argv[2], argv[3], argv[4]);
    }

    usage(argv[0]);
    return 1;
}
