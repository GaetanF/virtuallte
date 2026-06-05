#include "utils.h"

#include <stdint.h>

uint32_t get_le32(const void *p)
{
    const uint8_t *b = p;
    return ((uint32_t)b[0]) |
           ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) |
           ((uint32_t)b[3] << 24);
}

void put_le32(void *p, uint32_t v)
{
    uint8_t *b = p;
    b[0] = v & 0xff;
    b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff;
    b[3] = (v >> 24) & 0xff;
}
