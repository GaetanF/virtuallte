#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>

uint32_t get_le32(const void *p);
void put_le32(void *p, uint32_t v);

#endif
