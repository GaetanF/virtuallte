#include "../src/mbim_frontend/mbim_ntb.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

struct capture {
    int count;
    uint8_t data[128];
    uint32_t len;
};

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void capture_cb(void *user, const uint8_t *dg, uint32_t dg_len)
{
    struct capture *c = user;
    assert(dg_len <= sizeof(c->data));
    c->count++;
    c->len = dg_len;
    memcpy(c->data, dg, dg_len);
}

static void test_frame_deframe_roundtrip(void)
{
    static const uint8_t ip[] = {0x45, 0, 0, 20, 1, 2, 3, 4, 5};
    uint8_t ntb[256];
    struct capture c = {0};
    uint32_t len;
    uint16_t ndp;

    len = mbim_ntb16_frame_single(ntb, sizeof(ntb), ip, sizeof(ip), 0x1234);
    assert(len > 0);
    assert(le32(ntb) == MBIM_NTH16_SIGNATURE);
    assert(le16(ntb + 4) == 12);
    assert(le16(ntb + 6) == 0x1234);
    assert(le16(ntb + 8) == len);
    ndp = le16(ntb + 10);
    assert((ndp % 4) == 0);
    assert(le32(ntb + ndp) == MBIM_NDP16_SIGNATURE);
    assert(le16(ntb + ndp + 8) == 12);
    assert(le16(ntb + ndp + 10) == sizeof(ip));

    assert(mbim_ntb16_deframe(ntb, len, capture_cb, &c) == 1);
    assert(c.count == 1);
    assert(c.len == sizeof(ip));
    assert(!memcmp(c.data, ip, sizeof(ip)));
}

static void test_invalid_and_bogus_entries(void)
{
    uint8_t ntb[64];
    struct capture c = {0};

    memset(ntb, 0, sizeof(ntb));
    assert(mbim_ntb16_deframe(ntb, sizeof(ntb), capture_cb, &c) < 0);

    wr32(ntb + 0, MBIM_NTH16_SIGNATURE);
    wr16(ntb + 4, 12);
    wr16(ntb + 8, sizeof(ntb));
    wr16(ntb + 10, 16);
    wr32(ntb + 16, MBIM_NDP16_SIGNATURE);
    wr16(ntb + 20, 16);
    wr16(ntb + 22, 0);
    wr16(ntb + 24, 60);
    wr16(ntb + 26, 16); /* outside block, skipped */
    wr16(ntb + 28, 0);
    wr16(ntb + 30, 0);
    assert(mbim_ntb16_deframe(ntb, sizeof(ntb), capture_cb, &c) == 0);
    assert(c.count == 0);
}

static void test_ndp_backward_cycle_breaks(void)
{
    uint8_t ntb[96];
    struct capture c = {0};
    static const uint8_t ip[] = {0x45, 1, 2, 3};

    memset(ntb, 0, sizeof(ntb));
    memcpy(ntb + 12, ip, sizeof(ip));
    wr32(ntb + 0, MBIM_NTH16_SIGNATURE);
    wr16(ntb + 4, 12);
    wr16(ntb + 8, sizeof(ntb));
    wr16(ntb + 10, 32);

    wr32(ntb + 32, MBIM_NDP16_SIGNATURE);
    wr16(ntb + 36, 16);
    wr16(ntb + 38, 48);
    wr16(ntb + 40, 12);
    wr16(ntb + 42, sizeof(ip));

    wr32(ntb + 48, MBIM_NDP16_SIGNATURE);
    wr16(ntb + 52, 16);
    wr16(ntb + 54, 32); /* backward link: should break, not loop */
    wr16(ntb + 56, 12);
    wr16(ntb + 58, sizeof(ip));

    assert(mbim_ntb16_deframe(ntb, sizeof(ntb), capture_cb, &c) == 2);
    assert(c.count == 2);
}

int main(void)
{
    test_frame_deframe_roundtrip();
    test_invalid_and_bogus_entries();
    test_ndp_backward_cycle_breaks();
    return 0;
}
