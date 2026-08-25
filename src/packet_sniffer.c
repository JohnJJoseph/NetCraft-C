#include "packet_sniffer.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#ifdef HAVE_PCAP
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

static volatile int stop_flag = 0;

static void sigint_handler(int sig)
{
    (void)sig;
    stop_flag = 1;
}

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    int *count = (int *)user;
    if (stop_flag) return;

    struct ether_header *eth = (struct ether_header *)bytes;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return;

    struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ether_header));
    int ip_hdr_len = ip->ihl * 4;

    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip + ip_hdr_len);
        printf("TCP %s:%d -> %s:%d (len=%u)\n",
               src_ip, ntohs(tcp->source), dst_ip, ntohs(tcp->dest),
               ntohs(ip->tot_len) - ip_hdr_len - tcp->doff * 4);
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = (struct udphdr *)((u_char *)ip + ip_hdr_len);
        printf("UDP %s:%d -> %s:%d (len=%u)\n",
               src_ip, ntohs(udp->source), dst_ip, ntohs(udp->dest),
               ntohs(udp->len));
        break;
    }
    case IPPROTO_ICMP: {
        struct icmphdr *icmp = (struct icmphdr *)((u_char *)ip + ip_hdr_len);
        printf("ICMP %s -> %s type=%d\n", src_ip, dst_ip, icmp->type);
        break;
    }
    default:
        printf("IP proto=%d %s -> %s\n", ip->protocol, src_ip, dst_ip);
    }

    int data_len = h->caplen - (sizeof(struct ether_header) + ip_hdr_len);
    if (data_len > 0) {
        hex_dump((u_char *)ip + ip_hdr_len, data_len > 64 ? 64 : data_len);
    }

    (*count)--;
    if (*count == 0) stop_flag = 1;
}

int run_sniffer(const char *iface, const char *filter_expr, int count)
{
    signal(SIGINT, sigint_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        return -1;
    }

    struct bpf_program fp;
    if (filter_expr && *filter_expr) {
        if (pcap_compile(handle, &fp, filter_expr, 0, PCAP_NETMASK_UNKNOWN) < 0) {
            fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        if (pcap_setfilter(handle, &fp) < 0) {
            fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return -1;
        }
        pcap_freecode(&fp);
    }

    int remaining = count;
    while (!stop_flag && remaining != 0) {
        int ret = pcap_dispatch(handle, 1, packet_handler, (u_char *)&remaining);
        if (ret == -1) {
            fprintf(stderr, "pcap_dispatch: %s\n", pcap_geterr(handle));
            break;
        }
    }

    pcap_close(handle);
    return 0;
}
#else
int run_sniffer(const char *iface, const char *filter_expr, int count)
{
    (void)iface;
    (void)filter_expr;
    (void)count;
    fprintf(stderr, "packetkit was not built with libpcap support.\n");
    fprintf(stderr, "Install libpcap-dev and rebuild.\n");
    return -1;
}
#endif
