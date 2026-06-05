#include "../src/ue_engine/ue_nas_security.h"
#include "../src/ue_engine/ue_nas_decode.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;
    for (i = 0; i < out_len; i++) {
        unsigned int v = 0;
        int n = 0;
        assert(sscanf(hex + i * 2, "%2x%n", &v, &n) == 1);
        assert(n == 2);
        out[i] = (uint8_t)v;
    }
}

static void test_aes128_ecb_vector(void)
{
    uint8_t key[16], in[16], out[16], expected[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", key, sizeof(key));
    hex_to_bytes("00112233445566778899aabbccddeeff", in, sizeof(in));
    hex_to_bytes("69c4e0d86a7b0430d8cdb78070b4c55a", expected, sizeof(expected));
    ue_aes128_ecb_encrypt(key, in, out);
    assert(!memcmp(out, expected, sizeof(out)));
}

static void test_cmac_vector(void)
{
    uint8_t key[16], mac[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, sizeof(key));
    hex_to_bytes("bb1d6929e95937287fa37d129b756746", expected, sizeof(expected));
    ue_aes_cmac(key, NULL, 0, mac);
    assert(!memcmp(mac, expected, sizeof(mac)));
}

static void test_hmac_vector(void)
{
    uint8_t key[20], out[32], expected[32];
    memset(key, 0x0b, sizeof(key));
    hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b"
                 "881dc200c9833da726e9376c2e32cff7",
                 expected, sizeof(expected));
    ue_hmac_sha256(key, sizeof(key), (const uint8_t *)"Hi There", 8, out);
    assert(!memcmp(out, expected, sizeof(out)));
}

static void test_count_and_protect_parse_only(void)
{
    struct ue_nas_security_ctx ctx;
    uint8_t protected_msg[64];
    const uint8_t plain[] = {NAS_EPD_5GMM, NAS_SHT_NOT_PROTECTED, 0x43};
    struct ue_nas_sec_header_info hdr;
    const uint8_t *inner = NULL;
    size_t inner_len = 0;
    int len;

    memset(&ctx, 0, sizeof(ctx));
    ctx.active = true;
    ctx.int_alg = UE_NIA0;
    ctx.enc_alg = UE_NEA0;
    ctx.bearer = 1;
    ctx.ul_count.sqn = 0xff;
    ue_nas_count_increment(&ctx.ul_count);
    assert(ctx.ul_count.sqn == 0);
    assert(ctx.ul_count.overflow == 1);

    ctx.ul_count.sqn = 7;
    len = ue_nas_security_protect_with_sht(protected_msg, sizeof(protected_msg),
                                           &ctx, plain, sizeof(plain),
                                           NAS_SHT_INTEGRITY_PROTECTED);
    assert(len == 10);
    assert(protected_msg[0] == NAS_EPD_5GMM);
    assert(protected_msg[1] == NAS_SHT_INTEGRITY_PROTECTED);
    assert(protected_msg[2] == 0 && protected_msg[3] == 0 &&
           protected_msg[4] == 0 && protected_msg[5] == 0);
    assert(protected_msg[6] == 7);
    assert(!memcmp(protected_msg + 7, plain, sizeof(plain)));
    assert(ctx.ul_count.sqn == 8);

    assert(ue_nas_security_unwrap_parse_only(protected_msg, (size_t)len,
                                             &hdr, &inner, &inner_len) == 0);
    assert(hdr.epd == NAS_EPD_5GMM);
    assert(hdr.sht == NAS_SHT_INTEGRITY_PROTECTED);
    assert(hdr.sqn == 7);
    assert(inner_len == sizeof(plain));
    assert(!memcmp(inner, plain, sizeof(plain)));

    assert(ue_nas_security_protect_with_sht(protected_msg, 4, &ctx,
                                            plain, sizeof(plain),
                                            NAS_SHT_INTEGRITY_PROTECTED) < 0);
}

int main(void)
{
    test_aes128_ecb_vector();
    test_cmac_vector();
    test_hmac_vector();
    test_count_and_protect_parse_only();
    return 0;
}
