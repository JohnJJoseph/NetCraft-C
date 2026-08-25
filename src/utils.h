#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stdio.h>

uint16_t checksum(uint16_t *addr, int len);
int parse_mac(const char *str, uint8_t *mac);
void die(const char *msg);
void hex_dump(const uint8_t *data, int len);

#endif
