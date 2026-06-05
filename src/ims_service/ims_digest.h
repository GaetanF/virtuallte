#ifndef IMS_DIGEST_H
#define IMS_DIGEST_H

#include <stddef.h>
#include <stdint.h>

void ims_md5_hex(const uint8_t *data, size_t len, char out_hex[33]);
int ims_digest_md5_response(char out_hex[33],
                            const char *username,
                            const char *realm,
                            const uint8_t *password,
                            size_t password_len,
                            const char *method,
                            const char *uri,
                            const char *nonce,
                            const char *nc,
                            const char *cnonce,
                            const char *qop);

#endif
