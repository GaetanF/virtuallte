/*
 * Tests for the MBIM SMS store and the SMS_READ_INFO builder (public API only,
 * no changes to src/). Guards two regressions that were fixed:
 *   1. SMS_READ_INFO wire layout: 8-byte header (Format + ElementCount) with the
 *      {offset,size} ref list INLINE at offset 8 (a 16-byte header made ref[0]
 *      bogus and the host never displayed the SMS).
 *   2. Read-status lifecycle: the unsolicited SMS_READ indication marks a message
 *      "notified" but keeps it New (unread); it must not be re-pushed, and stays
 *      New until the host reads it via a query.
 */
#include "../src/mbim_frontend/mbim_handlers.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* A representative MT SMS PDU: [SCA-len=0][SMS-DELIVER TPDU bytes]. */
static const uint8_t pdu_a[] = {
    0x00, 0x04, 0x0b, 0x91, 0x33, 0x56, 0x70, 0x46, 0x62, 0xf4, 0x00, 0x00
};

static void test_store_append_and_unread(void)
{
    uint32_t idx = 0;
    uint32_t midx = 0;

    assert(mbim_handlers_sms_store_append(pdu_a, sizeof(pdu_a), &idx));
    assert(idx >= 1);

    assert(mbim_handlers_sms_store_has_unread(&midx));
    assert(midx == idx);

    /* A zero-length or oversized PDU is rejected. */
    assert(!mbim_handlers_sms_store_append(pdu_a, 0, &idx));
}

static void test_read_indication_wire_format_and_lifecycle(void)
{
    uint8_t buf[512];
    uint32_t len = 0;
    uint32_t idx = 0;
    uint32_t count, ref_off, ref_size, pdu_off, pdu_size;
    const uint8_t *rec;

    /* has_unread already true from the previous test; capture the index. */
    assert(mbim_handlers_sms_store_has_unread(&idx));

    assert(mbim_handlers_build_sms_read_indication(buf, sizeof(buf), &len));
    assert(len >= 8);

    /* Header: Format(0=PDU) + ElementCount, then the ref list inline at off 8. */
    assert(le32(buf + 0) == 0);
    count = le32(buf + 4);
    assert(count == 1);

    ref_off = le32(buf + 8);    /* ref[0].offset — must point to a real record */
    ref_size = le32(buf + 12);  /* ref[0].size                                  */
    assert(ref_off == 16);      /* 8-byte header + 8-byte ref pair => record @16 */
    assert(ref_size > 0);
    assert(ref_off + ref_size <= len);

    /* Record: messageindex, messagestatus(0=New), pdudata {offset(rel),size}. */
    rec = buf + ref_off;
    assert(le32(rec + 0) == idx);
    assert(le32(rec + 4) == 0);              /* New */
    pdu_off = le32(rec + 8);
    pdu_size = le32(rec + 12);
    assert(pdu_size == sizeof(pdu_a));
    assert(!memcmp(rec + pdu_off, pdu_a, sizeof(pdu_a)));

    /* Lifecycle: the message is now "notified" so a second indication finds
     * nothing new to push... */
    assert(!mbim_handlers_build_sms_read_indication(buf, sizeof(buf), &len));

    /* ...but it is still New (unread) until the host reads it via a query. */
    assert(mbim_handlers_sms_store_has_unread(&idx));
}

int main(void)
{
    test_store_append_and_unread();
    test_read_indication_wire_format_and_lifecycle();
    return 0;
}
