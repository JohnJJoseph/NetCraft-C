#include "utils.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

uint16_t checksum(uint16_t *addr, int len)
{
    uint32_t sum = 0;
    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }
    if (len == 1)
        sum += *(uint8_t *)addr;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

int parse_mac(const char *str, uint8_t *mac)
{
    int vals[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2],
               &vals[3], &vals[4], &vals[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)vals[i];
    return 0;
}

void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

void hex_dump(const uint8_t *data, int len)
{
    for (int i = 0; i < len; i++) {
        if (i > 0 && i % 16 == 0)
            printf("\n");
        else if (i > 0 && i % 8 == 0)
            printf("  ");
        printf("%02x ", data[i]);
    }
    printf("\n");
}
