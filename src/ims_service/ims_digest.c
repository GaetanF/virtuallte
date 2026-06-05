#include "ims_digest.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct md5_ctx {
    uint32_t a, b, c, d;
    uint64_t len;
    uint8_t buf[64];
    size_t buf_len;
};

static uint32_t rol32(uint32_t v, uint32_t n)
{
    return (v << n) | (v >> (32u - n));
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define F(x,y,z) (((x) & (y)) | (~(x) & (z)))
#define G(x,y,z) (((x) & (z)) | ((y) & ~(z)))
#define H(x,y,z) ((x) ^ (y) ^ (z))
#define I(x,y,z) ((y) ^ ((x) | ~(z)))
#define STEP(f,a,b,c,d,x,t,s) do { (a) += f((b),(c),(d)) + (x) + (uint32_t)(t); (a) = rol32((a), (s)); (a) += (b); } while (0)

static void md5_block(struct md5_ctx *ctx, const uint8_t block[64])
{
    uint32_t a = ctx->a, b = ctx->b, c = ctx->c, d = ctx->d;
    uint32_t x[16];
    int n;

    for (n = 0; n < 16; n++)
        x[n] = rd32le(block + n * 4);

    STEP(F,a,b,c,d,x[ 0],0xd76aa478, 7); STEP(F,d,a,b,c,x[ 1],0xe8c7b756,12);
    STEP(F,c,d,a,b,x[ 2],0x242070db,17); STEP(F,b,c,d,a,x[ 3],0xc1bdceee,22);
    STEP(F,a,b,c,d,x[ 4],0xf57c0faf, 7); STEP(F,d,a,b,c,x[ 5],0x4787c62a,12);
    STEP(F,c,d,a,b,x[ 6],0xa8304613,17); STEP(F,b,c,d,a,x[ 7],0xfd469501,22);
    STEP(F,a,b,c,d,x[ 8],0x698098d8, 7); STEP(F,d,a,b,c,x[ 9],0x8b44f7af,12);
    STEP(F,c,d,a,b,x[10],0xffff5bb1,17); STEP(F,b,c,d,a,x[11],0x895cd7be,22);
    STEP(F,a,b,c,d,x[12],0x6b901122, 7); STEP(F,d,a,b,c,x[13],0xfd987193,12);
    STEP(F,c,d,a,b,x[14],0xa679438e,17); STEP(F,b,c,d,a,x[15],0x49b40821,22);

    STEP(G,a,b,c,d,x[ 1],0xf61e2562, 5); STEP(G,d,a,b,c,x[ 6],0xc040b340, 9);
    STEP(G,c,d,a,b,x[11],0x265e5a51,14); STEP(G,b,c,d,a,x[ 0],0xe9b6c7aa,20);
    STEP(G,a,b,c,d,x[ 5],0xd62f105d, 5); STEP(G,d,a,b,c,x[10],0x02441453, 9);
    STEP(G,c,d,a,b,x[15],0xd8a1e681,14); STEP(G,b,c,d,a,x[ 4],0xe7d3fbc8,20);
    STEP(G,a,b,c,d,x[ 9],0x21e1cde6, 5); STEP(G,d,a,b,c,x[14],0xc33707d6, 9);
    STEP(G,c,d,a,b,x[ 3],0xf4d50d87,14); STEP(G,b,c,d,a,x[ 8],0x455a14ed,20);
    STEP(G,a,b,c,d,x[13],0xa9e3e905, 5); STEP(G,d,a,b,c,x[ 2],0xfcefa3f8, 9);
    STEP(G,c,d,a,b,x[ 7],0x676f02d9,14); STEP(G,b,c,d,a,x[12],0x8d2a4c8a,20);

    STEP(H,a,b,c,d,x[ 5],0xfffa3942, 4); STEP(H,d,a,b,c,x[ 8],0x8771f681,11);
    STEP(H,c,d,a,b,x[11],0x6d9d6122,16); STEP(H,b,c,d,a,x[14],0xfde5380c,23);
    STEP(H,a,b,c,d,x[ 1],0xa4beea44, 4); STEP(H,d,a,b,c,x[ 4],0x4bdecfa9,11);
    STEP(H,c,d,a,b,x[ 7],0xf6bb4b60,16); STEP(H,b,c,d,a,x[10],0xbebfbc70,23);
    STEP(H,a,b,c,d,x[13],0x289b7ec6, 4); STEP(H,d,a,b,c,x[ 0],0xeaa127fa,11);
    STEP(H,c,d,a,b,x[ 3],0xd4ef3085,16); STEP(H,b,c,d,a,x[ 6],0x04881d05,23);
    STEP(H,a,b,c,d,x[ 9],0xd9d4d039, 4); STEP(H,d,a,b,c,x[12],0xe6db99e5,11);
    STEP(H,c,d,a,b,x[15],0x1fa27cf8,16); STEP(H,b,c,d,a,x[ 2],0xc4ac5665,23);

    STEP(I,a,b,c,d,x[ 0],0xf4292244, 6); STEP(I,d,a,b,c,x[ 7],0x432aff97,10);
    STEP(I,c,d,a,b,x[14],0xab9423a7,15); STEP(I,b,c,d,a,x[ 5],0xfc93a039,21);
    STEP(I,a,b,c,d,x[12],0x655b59c3, 6); STEP(I,d,a,b,c,x[ 3],0x8f0ccc92,10);
    STEP(I,c,d,a,b,x[10],0xffeff47d,15); STEP(I,b,c,d,a,x[ 1],0x85845dd1,21);
    STEP(I,a,b,c,d,x[ 8],0x6fa87e4f, 6); STEP(I,d,a,b,c,x[15],0xfe2ce6e0,10);
    STEP(I,c,d,a,b,x[ 6],0xa3014314,15); STEP(I,b,c,d,a,x[13],0x4e0811a1,21);
    STEP(I,a,b,c,d,x[ 4],0xf7537e82, 6); STEP(I,d,a,b,c,x[11],0xbd3af235,10);
    STEP(I,c,d,a,b,x[ 2],0x2ad7d2bb,15); STEP(I,b,c,d,a,x[ 9],0xeb86d391,21);

    ctx->a += a; ctx->b += b; ctx->c += c; ctx->d += d;
}

static void md5_init(struct md5_ctx *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->a = 0x67452301; ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe; ctx->d = 0x10325476;
}

static void md5_update(struct md5_ctx *ctx, const uint8_t *data, size_t len)
{
    ctx->len += (uint64_t)len;
    while (len > 0) {
        size_t take = sizeof(ctx->buf) - ctx->buf_len;
        if (take > len)
            take = len;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
        if (ctx->buf_len == sizeof(ctx->buf)) {
            md5_block(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void md5_final(struct md5_ctx *ctx, uint8_t out[16])
{
    uint8_t pad[64] = { 0x80 };
    uint8_t len_le[8];
    uint64_t bits = ctx->len * 8u;
    size_t pad_len = ctx->buf_len < 56 ? 56 - ctx->buf_len : 120 - ctx->buf_len;

    for (int i = 0; i < 8; i++)
        len_le[i] = (uint8_t)(bits >> (8 * i));
    md5_update(ctx, pad, pad_len);
    md5_update(ctx, len_le, sizeof(len_le));
    wr32le(out, ctx->a); wr32le(out + 4, ctx->b);
    wr32le(out + 8, ctx->c); wr32le(out + 12, ctx->d);
}

static void hex16(const uint8_t in[16], char out[33])
{
    static const char h[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i * 2] = h[in[i] >> 4];
        out[i * 2 + 1] = h[in[i] & 0x0f];
    }
    out[32] = '\0';
}

void ims_md5_hex(const uint8_t *data, size_t len, char out_hex[33])
{
    struct md5_ctx ctx;
    uint8_t digest[16];

    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, digest);
    hex16(digest, out_hex);
}

static void md5_update_str(struct md5_ctx *ctx, const char *s)
{
    md5_update(ctx, (const uint8_t *)s, strlen(s));
}

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
                            const char *qop)
{
    struct md5_ctx ctx;
    uint8_t d[16];
    char ha1[33];
    char ha2[33];
    const uint8_t colon = ':';

    if (!out_hex || !username || !realm || !password || !method || !uri || !nonce)
        return -EINVAL;

    md5_init(&ctx);
    md5_update_str(&ctx, username); md5_update(&ctx, &colon, 1);
    md5_update_str(&ctx, realm); md5_update(&ctx, &colon, 1);
    md5_update(&ctx, password, password_len);
    md5_final(&ctx, d);
    hex16(d, ha1);

    md5_init(&ctx);
    md5_update_str(&ctx, method); md5_update(&ctx, &colon, 1);
    md5_update_str(&ctx, uri);
    md5_final(&ctx, d);
    hex16(d, ha2);

    md5_init(&ctx);
    md5_update_str(&ctx, ha1); md5_update(&ctx, &colon, 1);
    md5_update_str(&ctx, nonce); md5_update(&ctx, &colon, 1);
    if (qop && qop[0]) {
        if (!nc || !cnonce)
            return -EINVAL;
        md5_update_str(&ctx, nc); md5_update(&ctx, &colon, 1);
        md5_update_str(&ctx, cnonce); md5_update(&ctx, &colon, 1);
        md5_update_str(&ctx, qop); md5_update(&ctx, &colon, 1);
    }
    md5_update_str(&ctx, ha2);
    md5_final(&ctx, d);
    hex16(d, out_hex);
    return 0;
}
