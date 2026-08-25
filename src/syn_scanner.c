#include "syn_scanner.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>

struct pseudo_header {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  zero;
    uint8_t  protocol;
    uint16_t tcp_len;
};

static uint16_t tcp_checksum(struct iphdr *ip, struct tcphdr *tcp, int tcp_len)
{
    struct pseudo_header psh;
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_len = htons(tcp_len);

    int total_len = sizeof(psh) + tcp_len;
    char *buf = malloc(total_len);
    memcpy(buf, &psh, sizeof(psh));
    memcpy(buf + sizeof(psh), tcp, tcp_len);

    uint16_t res = checksum((uint16_t *)buf, total_len);
    free(buf);
    return res;
}

int syn_scan(const char *target, int start_port, int end_port, int timeout_ms)
{
    struct in_addr dst;
    struct hostent *he = gethostbyname(target);
    if (!he) {
        fprintf(stderr, "Failed to resolve %s\n", target);
        return -1;
    }
    dst.s_addr = *(uint32_t *)he->h_addr_list[0];
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dst, ip_str, sizeof(ip_str));

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        die("socket (try running as root)");
    }

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
        die("setsockopt IP_HDRINCL");

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr = dst;

    printf("SYN scanning %s ports %d-%d\n", ip_str, start_port, end_port);

    for (int port = start_port; port <= end_port; port++) {
        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct iphdr *ip = (struct iphdr *)packet;
        struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

        ip->ihl = 5;
        ip->version = 4;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id = htons(rand() & 0xFFFF);
        ip->frag_off = 0;
        ip->ttl = 64;
        ip->protocol = IPPROTO_TCP;
        ip->saddr = 0;
        ip->daddr = dst.s_addr;
        ip->check = 0;
        ip->check = checksum((uint16_t *)ip, sizeof(struct iphdr));

        tcp->source = htons(rand() & 0xFFFF);
        tcp->dest = htons(port);
        tcp->seq = htonl(rand());
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        tcp->check = 0;
        tcp->check = tcp_checksum(ip, tcp, sizeof(struct tcphdr));

        if (sendto(sock, packet, ntohs(ip->tot_len), 0,
                   (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto");
            continue;
        }

        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        struct timeval sel_tv = tv;
        int ret = select(sock + 1, &fds, NULL, NULL, &sel_tv);
        if (ret < 0) {
            perror("select");
            break;
        }
        if (ret == 0)
            continue;

        char recv_buf[4096];
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int n = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            perror("recvfrom");
            continue;
        }

        struct iphdr *rip = (struct iphdr *)recv_buf;
        int ip_hdr_len = rip->ihl * 4;
        struct tcphdr *rtcp = (struct tcphdr *)(recv_buf + ip_hdr_len);

        if (rtcp->syn && rtcp->ack && from.sin_addr.s_addr == dst.s_addr) {
            printf("Port %d is OPEN\n", port);
        }
    }

    close(sock);
    return 0;
}
