/*
 * Tests for the TS 24.011 RP-DATA codec (SMS over IP, TS 24.341):
 *   - ims_build_rp_data:        MO MBIM PDU [SCA][TPDU] -> RP-DATA (ms->n)
 *   - ims_rp_data_to_mbim_pdu:  MT RP-DATA (n->ms)      -> MBIM PDU [SCA][TPDU]
 */
#include "../src/ims_service/ims_rpdata.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void test_build_mo_with_sca(void)
{
    /* MBIM PDU: SCA = +33650764264 (len 7), then a 5-byte TPDU. */
    static const uint8_t mbim[] = {
        0x07, 0x91, 0x33, 0x56, 0x70, 0x46, 0x62, 0xf4,  /* [SCA-len][SCA]   */
        0x11, 0x00, 0x05, 0xaa, 0xbb                      /* TPDU (5 bytes)   */
    };
    uint8_t out[64];
    int len = ims_build_rp_data(mbim, sizeof(mbim), 0x2a, out, sizeof(out));

    assert(len == 17);                 /* 3 + 8 (SCA LV) + 1 + 5 */
    assert(out[0] == 0x00);            /* RP-MTI: RP-DATA (ms->n) */
    assert(out[1] == 0x2a);            /* RP-MR echoed */
    assert(out[2] == 0x00);            /* RP-OA len 0 (MO) */
    assert(!memcmp(out + 3, mbim, 8)); /* RP-DA = SCA LV */
    assert(out[11] == 5);              /* RP-UD len */
    assert(!memcmp(out + 12, mbim + 8, 5));
}

static void test_build_mo_without_sca(void)
{
    static const uint8_t mbim[] = {0x00, 0x21, 0x00, 0x0b};  /* SCA-len 0 + TPDU */
    uint8_t out[32];
    int len = ims_build_rp_data(mbim, sizeof(mbim), 1, out, sizeof(out));

    assert(len == 8);                  /* 3 + 1 + 1 + 3 */
    assert(out[0] == 0x00 && out[1] == 1);
    assert(out[2] == 0x00);            /* RP-OA len 0 */
    assert(out[3] == 0x00);            /* RP-DA len 0 (default SMSC) */
    assert(out[4] == 3);               /* RP-UD len */
    assert(!memcmp(out + 5, mbim + 1, 3));
}

static void test_build_rejects_bad_input(void)
{
    static const uint8_t mbim[] = {0x00, 0xaa, 0xbb};
    uint8_t out[32];

    assert(ims_build_rp_data(mbim, 0, 0, out, sizeof(out)) < 0);     /* empty */
    /* SCA-len consumes the whole buffer -> no TPDU left. */
    static const uint8_t only_sca[] = {0x05};
    assert(ims_build_rp_data(only_sca, sizeof(only_sca), 0, out, sizeof(out)) < 0);
    assert(ims_build_rp_data(mbim, sizeof(mbim), 0, out, 4) < 0);    /* tiny cap */
}

static void test_parse_mt(void)
{
    /* RP-DATA (n->ms): MTI=01, MR, OA = SCA LV (len 7), DA len 0, UD len 5. */
    static const uint8_t rp[] = {
        0x01, 0x2a,
        0x07, 0x91, 0x33, 0x56, 0x70, 0x46, 0x62, 0xf4,  /* RP-OA LV */
        0x00,                                            /* RP-DA len 0 */
        0x05, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4               /* RP-UD len + TPDU */
    };
    uint8_t out[64];
    uint8_t mr = 0;
    int len = ims_rp_data_to_mbim_pdu(rp, sizeof(rp), out, sizeof(out), &mr);

    assert(len == 13);                 /* 8 (SCA LV) + 5 (TPDU) */
    assert(mr == 0x2a);
    assert(!memcmp(out, rp + 2, 8));   /* SCA = RP-OA */
    assert(!memcmp(out + 8, rp + 12, 5));
}

static void test_parse_mt_with_ud_iei(void)
{
    /* Optional RP-UD IEI 0x41 before the length; empty RP-OA (no SMSC). */
    static const uint8_t rp[] = {
        0x01, 0x07,             /* MTI=RP-DATA, MR */
        0x00,                   /* RP-OA len 0 */
        0x00,                   /* RP-DA len 0 */
        0x41, 0x03,             /* RP-UD IEI + len */
        0xa0, 0xa1, 0xa2        /* TPDU */
    };
    uint8_t out[32];
    uint8_t mr = 0;
    int len = ims_rp_data_to_mbim_pdu(rp, sizeof(rp), out, sizeof(out), &mr);

    assert(len == 4);           /* 1 (SCA-len byte) + 3 (TPDU) */
    assert(mr == 0x07);
    assert(out[0] == 0x00);     /* SCA-len 0 reconstructed from empty RP-OA */
    assert(!memcmp(out + 1, rp + 6, 3));
}

static void test_parse_rejects_bad_input(void)
{
    static const uint8_t good[] = {
        0x01, 0x00, 0x00, 0x00, 0x02, 0xaa, 0xbb
    };
    uint8_t out[32];

    assert(ims_rp_data_to_mbim_pdu(good, 2, out, sizeof(out), NULL) < 0);   /* short */
    uint8_t bad_mti[sizeof(good)];
    memcpy(bad_mti, good, sizeof(good));
    bad_mti[0] = 0x00;                                                       /* not RP-DATA */
    assert(ims_rp_data_to_mbim_pdu(bad_mti, sizeof(bad_mti), out, sizeof(out), NULL) < 0);
    uint8_t zero_ud[] = {0x01, 0x00, 0x00, 0x00, 0x00};                      /* UD len 0 */
    assert(ims_rp_data_to_mbim_pdu(zero_ud, sizeof(zero_ud), out, sizeof(out), NULL) < 0);
}

int main(void)
{
    test_build_mo_with_sca();
    test_build_mo_without_sca();
    test_build_rejects_bad_input();
    test_parse_mt();
    test_parse_mt_with_ud_iei();
    test_parse_rejects_bad_input();
    return 0;
}
