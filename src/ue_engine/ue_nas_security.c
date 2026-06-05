/*
 * ue_nas_security.c - NAS security: Milenage, KDF, integrity, ciphering.
 *
 * Self-contained implementation — no external crypto library dependency.
 *
 * Contains:
 *   1. AES-128 ECB (minimal, for Milenage + CMAC + CTR)
 *   2. SHA-256 (for HMAC-SHA-256 KDF)
 *   3. HMAC-SHA-256 (for 3GPP KDF)
 *   4. AES-CMAC (RFC 4493, for NIA2 integrity)
 *   5. AES-128-CTR (for NEA2 ciphering)
 *   6. Milenage f1-f5* (3GPP TS 35.206)
 *   7. 3GPP KDF and 5G key derivation chain (TS 33.501)
 *   8. NAS security protect/unprotect
 *
 * Reference: 3GPP TS 33.501, TS 35.205-208, RFC 4493, FIPS 180-4
 */

#include "ue_nas_security.h"
#include "ue_nas_decode.h"  /* NAS_EPD_5GMM, NAS_SHT_* */

#include "../common/log.h"

#include <stdio.h>
#include <string.h>

/* ================================================================
 * 1. AES-128 ECB — Minimal implementation
 *
 * Standard AES-128 with pre-computed round keys.
 * Only ECB encrypt is needed (Milenage, CMAC subkey gen, CTR).
 * ================================================================ */

static const uint8_t aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t aes_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* GF(2^8) multiply for MixColumns */
static uint8_t gf_mul2(uint8_t x)
{
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void aes_key_expansion(const uint8_t *key, uint8_t rk[176])
{
    int i;
    uint8_t tmp[4];

    memcpy(rk, key, 16);

    for (i = 4; i < 44; i++) {
        memcpy(tmp, rk + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            uint8_t t = tmp[0];
            tmp[0] = aes_sbox[tmp[1]] ^ aes_rcon[i / 4];
            tmp[1] = aes_sbox[tmp[2]];
            tmp[2] = aes_sbox[tmp[3]];
            tmp[3] = aes_sbox[t];
        }
        rk[i * 4 + 0] = rk[(i - 4) * 4 + 0] ^ tmp[0];
        rk[i * 4 + 1] = rk[(i - 4) * 4 + 1] ^ tmp[1];
        rk[i * 4 + 2] = rk[(i - 4) * 4 + 2] ^ tmp[2];
        rk[i * 4 + 3] = rk[(i - 4) * 4 + 3] ^ tmp[3];
    }
}

static void aes_sub_bytes(uint8_t s[16])
{
    int i;
    for (i = 0; i < 16; i++)
        s[i] = aes_sbox[s[i]];
}

static void aes_shift_rows(uint8_t s[16])
{
    uint8_t t;
    /* Row 1: shift left 1 */
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
    /* Row 2: shift left 2 */
    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;
    /* Row 3: shift left 3 */
    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static void aes_mix_columns(uint8_t s[16])
{
    int c;
    for (c = 0; c < 4; c++) {
        uint8_t a0 = s[c * 4 + 0], a1 = s[c * 4 + 1];
        uint8_t a2 = s[c * 4 + 2], a3 = s[c * 4 + 3];
        s[c * 4 + 0] = gf_mul2(a0) ^ gf_mul2(a1) ^ a1 ^ a2 ^ a3;
        s[c * 4 + 1] = a0 ^ gf_mul2(a1) ^ gf_mul2(a2) ^ a2 ^ a3;
        s[c * 4 + 2] = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul2(a3) ^ a3;
        s[c * 4 + 3] = gf_mul2(a0) ^ a0 ^ a1 ^ a2 ^ gf_mul2(a3);
    }
}

static void aes_add_round_key(uint8_t s[16], const uint8_t *rk)
{
    int i;
    for (i = 0; i < 16; i++)
        s[i] ^= rk[i];
}

void ue_aes128_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out)
{
    uint8_t rk[176];
    uint8_t s[16];
    int r;

    aes_key_expansion(key, rk);
    memcpy(s, in, 16);

    aes_add_round_key(s, rk);
    for (r = 1; r < 10; r++) {
        aes_sub_bytes(s);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, rk + r * 16);
    }
    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_add_round_key(s, rk + 160);

    memcpy(out, s, 16);
}

/* ================================================================
 * 2. SHA-256 (FIPS 180-4)
 * ================================================================ */

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_transform(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = h[0]; b = h[1]; c = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];

    for (i = 0; i < 64; i++) {
        uint32_t S1 = ROR32(e, 6) ^ ROR32(e, 11) ^ ROR32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        t1 = hh + S1 + ch + sha256_k[i] + w[i];
        uint32_t S0 = ROR32(a, 2) ^ ROR32(a, 13) ^ ROR32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        t2 = S0 + maj;

        hh = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t block[64];
    size_t i, blocks, rem;
    uint64_t bit_len;

    /* Process full blocks */
    blocks = len / 64;
    for (i = 0; i < blocks; i++)
        sha256_transform(h, msg + i * 64);

    /* Pad */
    rem = len % 64;
    memset(block, 0, 64);
    if (rem > 0)
        memcpy(block, msg + blocks * 64, rem);
    block[rem] = 0x80;

    if (rem >= 56) {
        sha256_transform(h, block);
        memset(block, 0, 64);
    }

    bit_len = (uint64_t)len * 8;
    block[56] = (uint8_t)(bit_len >> 56);
    block[57] = (uint8_t)(bit_len >> 48);
    block[58] = (uint8_t)(bit_len >> 40);
    block[59] = (uint8_t)(bit_len >> 32);
    block[60] = (uint8_t)(bit_len >> 24);
    block[61] = (uint8_t)(bit_len >> 16);
    block[62] = (uint8_t)(bit_len >> 8);
    block[63] = (uint8_t)(bit_len);
    sha256_transform(h, block);

    for (i = 0; i < 8; i++) {
        out[i * 4 + 0] = (uint8_t)(h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(h[i]);
    }
}

/* ================================================================
 * 3. HMAC-SHA-256 (RFC 2104)
 * ================================================================ */

void ue_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len,
                    uint8_t *out)
{
    uint8_t k_pad[64];
    uint8_t inner_hash[32];
    uint8_t inner_buf[64 + 8192]; /* max msg ~8K */
    uint8_t outer_buf[64 + 32];
    size_t i;

    /* If key > 64 bytes, hash it first */
    if (key_len > 64) {
        uint8_t key_hash[32];
        sha256(key, key_len, key_hash);
        memset(k_pad, 0, 64);
        memcpy(k_pad, key_hash, 32);
    } else {
        memset(k_pad, 0, 64);
        memcpy(k_pad, key, key_len);
    }

    /* Inner: SHA-256((K XOR ipad) || msg) */
    for (i = 0; i < 64; i++)
        inner_buf[i] = k_pad[i] ^ 0x36;

    if (msg_len <= sizeof(inner_buf) - 64) {
        memcpy(inner_buf + 64, msg, msg_len);
        sha256(inner_buf, 64 + msg_len, inner_hash);
    } else {
        /* Fallback for oversized messages — shouldn't happen in NAS */
        sha256(inner_buf, 64, inner_hash);
    }

    /* Outer: SHA-256((K XOR opad) || inner_hash) */
    for (i = 0; i < 64; i++)
        outer_buf[i] = k_pad[i] ^ 0x5c;
    memcpy(outer_buf + 64, inner_hash, 32);
    sha256(outer_buf, 96, out);
}

/* ================================================================
 * 4. AES-CMAC (RFC 4493)
 * ================================================================ */

static void cmac_shift_left(const uint8_t *in, uint8_t *out)
{
    int i;
    uint8_t carry = 0;
    for (i = 15; i >= 0; i--) {
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry = (in[i] & 0x80) ? 1 : 0;
    }
    if (in[0] & 0x80)
        out[15] ^= 0x87;
}

void ue_aes_cmac(const uint8_t *key, const uint8_t *msg, size_t msg_len,
                 uint8_t *mac)
{
    uint8_t k1[16], k2[16], l[16], x[16], y[16], m_last[16];
    size_t n, i;
    int flag;

    /* Generate subkeys K1, K2 */
    memset(l, 0, 16);
    ue_aes128_ecb_encrypt(key, l, l);   /* L = AES_K(0^128) */
    cmac_shift_left(l, k1);
    cmac_shift_left(k1, k2);

    n = (msg_len + 15) / 16;
    if (n == 0) {
        n = 1;
        flag = 0;
    } else {
        flag = (msg_len % 16 == 0) ? 1 : 0;
    }

    /* M_last = M_n XOR K1 (complete) or (M_n || 10^j) XOR K2 (incomplete) */
    if (flag) {
        for (i = 0; i < 16; i++)
            m_last[i] = msg[(n - 1) * 16 + i] ^ k1[i];
    } else {
        size_t rem = msg_len % 16;
        memset(m_last, 0, 16);
        if (rem > 0)
            memcpy(m_last, msg + (n - 1) * 16, rem);
        m_last[rem] = 0x80;
        for (i = 0; i < 16; i++)
            m_last[i] ^= k2[i];
    }

    /* CBC-MAC */
    memset(x, 0, 16);
    for (i = 0; i < n - 1; i++) {
        size_t j;
        for (j = 0; j < 16; j++)
            y[j] = x[j] ^ msg[i * 16 + j];
        ue_aes128_ecb_encrypt(key, y, x);
    }
    {
        size_t j;
        for (j = 0; j < 16; j++)
            y[j] = x[j] ^ m_last[j];
        ue_aes128_ecb_encrypt(key, y, mac);
    }
}

/* ================================================================
 * 5. AES-128-CTR (for NEA2)
 *
 * IV construction for 3GPP NEA2 (TS 33.501):
 *   IV[0..3]  = COUNT (big-endian)
 *   IV[4]     = (bearer << 3) | (direction << 2)
 *   IV[5..15] = 0
 * ================================================================ */

static void aes128_ctr(const uint8_t *key, const uint8_t iv[16],
                       uint8_t *data, size_t len)
{
    uint8_t ctr[16], ks[16];
    size_t i, j;

    memcpy(ctr, iv, 16);

    for (i = 0; i < len; i += 16) {
        ue_aes128_ecb_encrypt(key, ctr, ks);
        for (j = 0; j < 16 && (i + j) < len; j++)
            data[i + j] ^= ks[j];

        /* Increment counter (last 4 bytes, big-endian) */
        {
            int k;
            for (k = 15; k >= 12; k--) {
                ctr[k]++;
                if (ctr[k] != 0)
                    break;
            }
        }
    }
}

/* ================================================================
 * 6. Milenage f1-f5* (3GPP TS 35.206)
 * ================================================================ */

/* Rotation constants */
#define MILENAGE_R1 8
#define MILENAGE_R2 0
#define MILENAGE_R3 4
#define MILENAGE_R4 8
#define MILENAGE_R5 12

static void milenage_rotate(const uint8_t *in, uint8_t *out, int r)
{
    int i;
    for (i = 0; i < 16; i++)
        out[i] = in[(i + r) % 16];
}

int ue_milenage_opc(uint8_t *opc, const uint8_t *k, const uint8_t *op)
{
    int i;
    ue_aes128_ecb_encrypt(k, op, opc);
    for (i = 0; i < 16; i++)
        opc[i] ^= op[i];
    return 0;
}

int ue_milenage_compute(const uint8_t *opc, const uint8_t *k,
                        const uint8_t *rand, const uint8_t *sqn,
                        const uint8_t *amf,
                        struct ue_milenage_result *out)
{
    uint8_t temp[16], tmp1[16], tmp2[16], tmp3[16];
    uint8_t in1[16];
    int i;

    if (!opc || !k || !rand || !sqn || !amf || !out)
        return -1;

    memset(out, 0, sizeof(*out));

    /* TEMP = AES_K(RAND XOR OPc) */
    for (i = 0; i < 16; i++)
        tmp1[i] = rand[i] ^ opc[i];
    ue_aes128_ecb_encrypt(k, tmp1, temp);

    /* f1/f1*: MAC-A and MAC-S */
    /* IN1 = SQN || AMF || SQN || AMF */
    memcpy(in1, sqn, 6);
    memcpy(in1 + 6, amf, 2);
    memcpy(in1 + 8, sqn, 6);
    memcpy(in1 + 14, amf, 2);

    /* tmp3 = rot(IN1 XOR OPc, r1) XOR TEMP XOR c1(=0) */
    for (i = 0; i < 16; i++)
        tmp1[i] = in1[i] ^ opc[i];
    milenage_rotate(tmp1, tmp3, MILENAGE_R1);
    for (i = 0; i < 16; i++)
        tmp3[i] ^= temp[i];
    /* c1 = 0, no XOR needed */

    /* OUT1 = AES_K(tmp3) XOR OPc */
    ue_aes128_ecb_encrypt(k, tmp3, tmp1);
    for (i = 0; i < 16; i++)
        tmp1[i] ^= opc[i];

    memcpy(out->mac_a, tmp1, 8);     /* f1: MAC-A */
    memcpy(out->mac_s, tmp1 + 8, 8); /* f1*: MAC-S */

    /* f2, f5: RES and AK (no rotation, c2 = 0x01 at byte 15) */
    for (i = 0; i < 16; i++)
        tmp1[i] = temp[i] ^ opc[i];
    tmp1[15] ^= 0x01;
    ue_aes128_ecb_encrypt(k, tmp1, tmp2);
    for (i = 0; i < 16; i++)
        tmp2[i] ^= opc[i];

    memcpy(out->ak, tmp2, 6);        /* f5: AK */
    memcpy(out->res, tmp2 + 8, 8);   /* f2: RES */

    /* f3: CK (rotate r3=4, c3 = 0x02 at byte 15) */
    for (i = 0; i < 16; i++)
        tmp1[i] = temp[i] ^ opc[i];
    milenage_rotate(tmp1, tmp3, MILENAGE_R3);
    tmp3[15] ^= 0x02;
    ue_aes128_ecb_encrypt(k, tmp3, out->ck);
    for (i = 0; i < 16; i++)
        out->ck[i] ^= opc[i];

    /* f4: IK (rotate r4=8, c4 = 0x04 at byte 15) */
    for (i = 0; i < 16; i++)
        tmp1[i] = temp[i] ^ opc[i];
    milenage_rotate(tmp1, tmp3, MILENAGE_R4);
    tmp3[15] ^= 0x04;
    ue_aes128_ecb_encrypt(k, tmp3, out->ik);
    for (i = 0; i < 16; i++)
        out->ik[i] ^= opc[i];

    /* f5*: AK* (rotate r5=12, c5 = 0x08 at byte 15) */
    for (i = 0; i < 16; i++)
        tmp1[i] = temp[i] ^ opc[i];
    milenage_rotate(tmp1, tmp3, MILENAGE_R5);
    tmp3[15] ^= 0x08;
    ue_aes128_ecb_encrypt(k, tmp3, tmp2);
    for (i = 0; i < 16; i++)
        tmp2[i] ^= opc[i];
    memcpy(out->ak_star, tmp2, 6);

    return 0;
}

/* ================================================================
 * 7. 3GPP KDF (TS 33.220) and 5G key derivation (TS 33.501 Annex A)
 * ================================================================ */

void ue_3gpp_kdf(const uint8_t *key, size_t key_len,
                 uint8_t fc,
                 const uint8_t *p0, uint16_t l0,
                 const uint8_t *p1, uint16_t l1,
                 uint8_t *out)
{
    uint8_t s[512];
    size_t pos = 0;

    s[pos++] = fc;

    if (p0 && l0 > 0) {
        memcpy(s + pos, p0, l0);
        pos += l0;
        s[pos++] = (uint8_t)(l0 >> 8);
        s[pos++] = (uint8_t)(l0);
    }

    if (p1 && l1 > 0) {
        memcpy(s + pos, p1, l1);
        pos += l1;
        s[pos++] = (uint8_t)(l1 >> 8);
        s[pos++] = (uint8_t)(l1);
    }

    ue_hmac_sha256(key, key_len, s, pos, out);
}

/*
 * Extended KDF with 3 parameters.
 */
static void kdf_3p(const uint8_t *key, size_t key_len,
                   uint8_t fc,
                   const uint8_t *p0, uint16_t l0,
                   const uint8_t *p1, uint16_t l1,
                   const uint8_t *p2, uint16_t l2,
                   uint8_t *out)
{
    uint8_t s[512];
    size_t pos = 0;

    s[pos++] = fc;

    if (p0 && l0 > 0) {
        memcpy(s + pos, p0, l0);
        pos += l0;
        s[pos++] = (uint8_t)(l0 >> 8);
        s[pos++] = (uint8_t)(l0);
    }
    if (p1 && l1 > 0) {
        memcpy(s + pos, p1, l1);
        pos += l1;
        s[pos++] = (uint8_t)(l1 >> 8);
        s[pos++] = (uint8_t)(l1);
    }
    if (p2 && l2 > 0) {
        memcpy(s + pos, p2, l2);
        pos += l2;
        s[pos++] = (uint8_t)(l2 >> 8);
        s[pos++] = (uint8_t)(l2);
    }

    ue_hmac_sha256(key, key_len, s, pos, out);
}

int ue_nas_derive_keys(const uint8_t *ck, const uint8_t *ik,
                       const uint8_t *ak, const uint8_t *rand,
                       const uint8_t *res, const uint8_t *sqn,
                       const char *snn, const char *supi,
                       const uint8_t *abba, size_t abba_len,
                       uint8_t int_alg_id, uint8_t enc_alg_id,
                       struct ue_nas_keys *out)
{
    uint8_t ck_ik[32];          /* CK || IK */
    uint8_t sqn_xor_ak[6];
    size_t snn_len, supi_len;
    int i;

    if (!ck || !ik || !ak || !sqn || !snn || !out)
        return -1;

    memset(out, 0, sizeof(*out));
    memcpy(ck_ik, ck, 16);
    memcpy(ck_ik + 16, ik, 16);

    for (i = 0; i < 6; i++)
        sqn_xor_ak[i] = sqn[i] ^ ak[i];

    snn_len = strlen(snn);
    supi_len = supi ? strlen(supi) : 0;

    /*
     * KAUSF = KDF(CK||IK, 0x6A, SNN, SQN XOR AK)
     * TS 33.501 A.2
     */
    ue_3gpp_kdf(ck_ik, 32, 0x6A,
                (const uint8_t *)snn, (uint16_t)snn_len,
                sqn_xor_ak, 6,
                out->kausf);

    /*
     * KSEAF = KDF(KAUSF, 0x6C, SNN)
     * TS 33.501 A.6
     */
    ue_3gpp_kdf(out->kausf, 32, 0x6C,
                (const uint8_t *)snn, (uint16_t)snn_len,
                NULL, 0,
                out->kseaf);

    /*
     * KAMF = KDF(KSEAF, 0x6D, SUPI, ABBA)
     * TS 33.501 A.7
     */
    ue_3gpp_kdf(out->kseaf, 32, 0x6D,
                (const uint8_t *)supi, (uint16_t)supi_len,
                abba, (uint16_t)abba_len,
                out->kamf);

    /*
     * KNASenc = KDF(KAMF, 0x69, alg_type=0x01, enc_alg_id)[16..31]
     * KNASint = KDF(KAMF, 0x69, alg_type=0x02, int_alg_id)[16..31]
     * TS 33.501 A.8
     */
    {
        uint8_t kdf_out[32];
        uint8_t alg_type, alg_id;

        /* KNASenc */
        alg_type = 0x01;
        alg_id = enc_alg_id;
        ue_3gpp_kdf(out->kamf, 32, 0x69,
                    &alg_type, 1,
                    &alg_id, 1,
                    kdf_out);
        memcpy(out->knas_enc, kdf_out + 16, 16);

        /* KNASint */
        alg_type = 0x02;
        alg_id = int_alg_id;
        ue_3gpp_kdf(out->kamf, 32, 0x69,
                    &alg_type, 1,
                    &alg_id, 1,
                    kdf_out);
        memcpy(out->knas_int, kdf_out + 16, 16);
    }

    /*
     * RES* = KDF(CK||IK, 0x6B, SNN, RAND, RES)[16..31]
     * TS 33.501 A.4
     */
    if (rand && res) {
        uint8_t kdf_out[32];
        kdf_3p(ck_ik, 32, 0x6B,
               (const uint8_t *)snn, (uint16_t)snn_len,
               rand, 16,
               res, 8,
               kdf_out);
        memcpy(out->res_star, kdf_out + 16, 16);
    }

    return 0;
}

int ue_nas_derive_knas_from_kamf(const uint8_t *kamf,
                                 uint8_t int_alg_id,
                                 uint8_t enc_alg_id,
                                 uint8_t *knas_int,
                                 uint8_t *knas_enc)
{
    uint8_t kdf_out[32];
    uint8_t alg_type;
    uint8_t alg_id;

    if (!kamf || !knas_int || !knas_enc)
        return -1;

    /* KNASenc = KDF(KAMF, FC=0x69, P0=0x01, P1=enc_alg_id) */
    alg_type = 0x01;
    alg_id = enc_alg_id;
    ue_3gpp_kdf(kamf, 32, 0x69,
                &alg_type, 1,
                &alg_id, 1,
                kdf_out);
    memcpy(knas_enc, kdf_out + 16, 16);

    /* KNASint = KDF(KAMF, FC=0x69, P0=0x02, P1=int_alg_id) */
    alg_type = 0x02;
    alg_id = int_alg_id;
    ue_3gpp_kdf(kamf, 32, 0x69,
                &alg_type, 1,
                &alg_id, 1,
                kdf_out);
    memcpy(knas_int, kdf_out + 16, 16);

    return 0;
}

/* ================================================================
 * 8. NAS integrity and ciphering
 * ================================================================ */

uint32_t ue_nas_compute_mac(enum ue_nas_integrity_alg alg,
                            uint32_t count, uint8_t bearer,
                            uint8_t direction,
                            const uint8_t *key,
                            const uint8_t *msg, size_t msg_len)
{
    if (alg == UE_NIA0)
        return 0;

    if (alg == UE_NIA2) {
        /*
         * EIA2: AES-CMAC over (COUNT || BEARER || DIRECTION || msg)
         * Input: COUNT(4) + bearer(5b)+dir(1b)+pad(26b) = 4 bytes + msg
         * Total: 8 + msg_len
         */
        uint8_t cmac_input[8 + 8192];
        uint8_t mac_out[16];
        size_t total;

        if (msg_len > 8192)
            return 0;

        cmac_input[0] = (uint8_t)(count >> 24);
        cmac_input[1] = (uint8_t)(count >> 16);
        cmac_input[2] = (uint8_t)(count >> 8);
        cmac_input[3] = (uint8_t)(count);
        cmac_input[4] = (uint8_t)((bearer << 3) | ((direction & 1) << 2));
        cmac_input[5] = 0;
        cmac_input[6] = 0;
        cmac_input[7] = 0;

        memcpy(cmac_input + 8, msg, msg_len);
        total = 8 + msg_len;

        ue_aes_cmac(key, cmac_input, total, mac_out);

        return ((uint32_t)mac_out[0] << 24) | ((uint32_t)mac_out[1] << 16) |
               ((uint32_t)mac_out[2] << 8) | (uint32_t)mac_out[3];
    }

    /* NIA1 (SNOW3G) not implemented */
    return 0;
}

int ue_nas_cipher(enum ue_nas_ciphering_alg alg,
                  uint32_t count, uint8_t bearer,
                  uint8_t direction,
                  const uint8_t *key,
                  uint8_t *data, size_t data_len)
{
    if (alg == UE_NEA0)
        return 0;  /* null ciphering — no-op */

    if (alg == UE_NEA2) {
        /*
         * EEA2: AES-128-CTR
         * IV[0..3] = COUNT (big-endian)
         * IV[4]    = (bearer << 3) | (direction << 2)
         * IV[5..15] = 0
         */
        uint8_t iv[16];
        memset(iv, 0, 16);
        iv[0] = (uint8_t)(count >> 24);
        iv[1] = (uint8_t)(count >> 16);
        iv[2] = (uint8_t)(count >> 8);
        iv[3] = (uint8_t)(count);
        iv[4] = (uint8_t)((bearer << 3) | ((direction & 1) << 2));

        aes128_ctr(key, iv, data, data_len);
        return 0;
    }

    /* NEA1 (SNOW3G) not implemented */
    return -1;
}

/* ================================================================
 * 9. NAS security protect/unprotect
 * ================================================================ */

int ue_nas_security_protect_with_sht(uint8_t *buf, size_t buf_len,
                                     struct ue_nas_security_ctx *ctx,
                                     const uint8_t *plain, size_t plain_len,
                                     uint8_t sht)
{
    size_t total;
    uint32_t count;
    uint32_t mac;
    uint8_t sqn_byte;
    bool cipher_payload;

    if (!buf || !ctx || !ctx->active || !plain || plain_len == 0)
        return -1;
    if (sht != NAS_SHT_INTEGRITY_PROTECTED &&
        sht != NAS_SHT_INTEGRITY_PROTECTED_CIPHERED &&
        sht != NAS_SHT_INTEGRITY_PROTECTED_NEW_CTX &&
        sht != NAS_SHT_INTEGRITY_PROTECTED_CIPHERED_NEW_CTX)
        return -1;

    /* EPD(1) + SHT(1) + MAC(4) + SQN(1) + plain */
    total = 7 + plain_len;
    if (buf_len < total)
        return -1;

    count = ue_nas_count_value(&ctx->ul_count);
    sqn_byte = ctx->ul_count.sqn;
    cipher_payload = (sht == NAS_SHT_INTEGRITY_PROTECTED_CIPHERED ||
                      sht == NAS_SHT_INTEGRITY_PROTECTED_CIPHERED_NEW_CTX);

    /* Build the protected message */
    buf[0] = NAS_EPD_5GMM;
    buf[1] = sht;
    /* MAC placeholder — fill after computing */
    buf[6] = sqn_byte;

    /* Copy plain NAS message */
    memcpy(buf + 7, plain, plain_len);

    {
        size_t i;
        size_t dump = plain_len < 96 ? plain_len : 96;
        char hex[512] = "";
        int hpos = 0;
        for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                             "%s%02x", i ? " " : "", buf[7 + i]);
        LOG_TRC(NAS, "UL protected NAS plain len=%zu hex=%s%s",
                plain_len, hex, plain_len > dump ? " ..." : "");
    }

    /* Cipher the payload only for ciphered SHT values. */
    if (cipher_payload) {
        ue_nas_cipher(ctx->enc_alg, count, ctx->bearer, 0 /* uplink */,
                      ctx->keys.knas_enc, buf + 7, plain_len);
    }

    /* Compute MAC over SQN + ciphered payload (bytes 6+) */
    mac = ue_nas_compute_mac(ctx->int_alg, count, ctx->bearer, 0 /* uplink */,
                             ctx->keys.knas_int, buf + 6, 1 + plain_len);

    buf[2] = (uint8_t)(mac >> 24);
    buf[3] = (uint8_t)(mac >> 16);
    buf[4] = (uint8_t)(mac >> 8);
    buf[5] = (uint8_t)(mac);

    LOG_TRC(NAS, "UL protected NAS: sht=0x%02x count=0x%08x sqn=%u int_alg=%u enc_alg=%u mac=0x%08x",
            sht, (unsigned)count, (unsigned)sqn_byte,
            (unsigned)ctx->int_alg, (unsigned)ctx->enc_alg, (unsigned)mac);
    {
        size_t i;
        size_t dump = total < 120 ? total : 120;
        char hex[640] = "";
        int hpos = 0;
        for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                             "%s%02x", i ? " " : "", buf[i]);
        LOG_TRC(NAS, "UL protected NAS pdu len=%zu hex=%s%s",
                total, hex, total > dump ? " ..." : "");
    }

    /* Increment uplink COUNT */
    ue_nas_count_increment(&ctx->ul_count);

    return (int)total;
}

int ue_nas_security_protect(uint8_t *buf, size_t buf_len,
                            struct ue_nas_security_ctx *ctx,
                            const uint8_t *plain, size_t plain_len)
{
    return ue_nas_security_protect_with_sht(buf, buf_len, ctx, plain, plain_len,
                                            NAS_SHT_INTEGRITY_PROTECTED_CIPHERED);
}

int ue_nas_security_unprotect(uint8_t *data, size_t len,
                              struct ue_nas_security_ctx *ctx,
                              const uint8_t **out_plain, size_t *out_plain_len)
{
    uint32_t received_mac, computed_mac;
    uint8_t sqn_byte;
    uint32_t count;

    if (!data || !ctx || !ctx->active || !out_plain || !out_plain_len)
        return -1;
    if (len < 7)
        return -1;

    /* data[0] = EPD, data[1] = SHT, data[2..5] = MAC, data[6] = SQN */
    if (data[0] != NAS_EPD_5GMM)
        return -1;
    if (data[1] == NAS_SHT_NOT_PROTECTED) {
        /* Not protected — return as-is */
        *out_plain = data;
        *out_plain_len = len;
        return 0;
    }

    received_mac = ((uint32_t)data[2] << 24) | ((uint32_t)data[3] << 16) |
                   ((uint32_t)data[4] << 8) | (uint32_t)data[5];
    sqn_byte = data[6];

    LOG_TRC(NAS, "DL protected NAS: len=%zu sht=0x%02x sqn_rx=%u", len, data[1], sqn_byte);
    LOG_TRC(NAS, "DL protected NAS keys/algo: int_alg=%u enc_alg=%u bearer=%u dir=1",
            (unsigned)ctx->int_alg, (unsigned)ctx->enc_alg, (unsigned)ctx->bearer);
    /* Key material (knas_int/knas_enc) is never logged, even at trace level. */

    /*
     * Estimate downlink COUNT from received SQN.
     * If received SQN < expected SQN, overflow has incremented.
     */
    {
        struct ue_nas_count est = ctx->dl_count;
        LOG_TRC(NAS, "DL protected NAS count before: overflow=%u sqn=%u",
                (unsigned)est.overflow, (unsigned)est.sqn);
        if (sqn_byte < est.sqn)
            est.overflow++;
        est.sqn = sqn_byte;
        count = ue_nas_count_value(&est);
        LOG_TRC(NAS, "DL protected NAS count used: overflow=%u sqn=%u count=0x%08x",
                (unsigned)est.overflow, (unsigned)est.sqn, (unsigned)count);

        /* Verify MAC */
        computed_mac = ue_nas_compute_mac(ctx->int_alg, count, ctx->bearer,
                                          1 /* downlink */,
                                          ctx->keys.knas_int,
                                          data + 6, len - 6);

        LOG_TRC(NAS, "DL protected NAS MAC: rx=0x%08x calc=0x%08x",
                (unsigned)received_mac, (unsigned)computed_mac);

        if (ctx->int_alg != UE_NIA0 && received_mac != computed_mac) {
            LOG_WRN(NAS, "DL protected NAS integrity check FAILED");
            return -1;  /* integrity check failed */
        }

        /* Update downlink COUNT */
        ctx->dl_count = est;
    }

    /* Decipher payload (bytes 7+) */
    ue_nas_cipher(ctx->enc_alg, count, ctx->bearer, 1 /* downlink */,
                  ctx->keys.knas_enc, data + 7, len - 7);

    {
        size_t i;
        size_t dump = (len - 7) < 96 ? (len - 7) : 96;
        char hex[512] = "";
        int hpos = 0;
        for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                             "%s%02x", i ? " " : "", data[7 + i]);
        LOG_TRC(NAS, "DL protected NAS inner len=%zu hex=%s%s",
                len - 7, hex, (len - 7) > dump ? " ..." : "");
    }

    *out_plain = data + 7;
    *out_plain_len = len - 7;
    return 0;
}

int ue_nas_security_unwrap_parse_only(const uint8_t *data, size_t len,
                                      struct ue_nas_sec_header_info *hdr,
                                      const uint8_t **out_inner,
                                      size_t *out_inner_len)
{
    if (!data || !hdr || !out_inner || !out_inner_len)
        return -1;
    if (len < 7)
        return -1;

    if (data[0] != NAS_EPD_5GMM)
        return -1;
    if (data[1] == NAS_SHT_NOT_PROTECTED)
        return -1;

    hdr->epd = data[0];
    hdr->sht = data[1];
    hdr->mac = ((uint32_t)data[2] << 24) | ((uint32_t)data[3] << 16) |
               ((uint32_t)data[4] << 8) | (uint32_t)data[5];
    hdr->sqn = data[6];

    *out_inner = data + 7;
    *out_inner_len = len - 7;
    return 0;
}
