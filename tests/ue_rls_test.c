#include "../src/ue_engine/ue_rls.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint64_t be64(const uint8_t *p)
{
    return ((uint64_t)be32(p) << 32) | (uint64_t)be32(p + 4);
}

static void test_heartbeat_roundtrip(void)
{
    uint8_t buf[64];
    struct ue_rls_message msg;
    int len;

    len = ue_rls_encode_heartbeat(buf, sizeof(buf),
                                  0x0102030405060708ULL,
                                  -1, 2, -3);
    assert(len == 25);
    assert(buf[0] == UE_RLS_COMPAT_MARKER);
    assert(buf[1] == UE_RLS_VERSION_MAJOR);
    assert(buf[2] == UE_RLS_VERSION_MINOR);
    assert(buf[3] == UE_RLS_VERSION_PATCH);
    assert(buf[4] == UE_RLS_HEARTBEAT);
    assert(be64(buf + 5) == 0x0102030405060708ULL);
    assert(be32(buf + 13) == 0xffffffffu);
    assert(be32(buf + 17) == 2u);
    assert(be32(buf + 21) == 0xfffffffdu);

    assert(ue_rls_decode(buf, (size_t)len, &msg) == 0);
    assert(msg.type == UE_RLS_HEARTBEAT);
    assert(msg.u.heartbeat.sti == 0x0102030405060708ULL);
    assert(msg.u.heartbeat.sim_pos_x == -1);
    assert(msg.u.heartbeat.sim_pos_y == 2);
    assert(msg.u.heartbeat.sim_pos_z == -3);
}

static void test_data_pdu_roundtrip(void)
{
    static const uint8_t payload[] = {0x45, 0x00, 0x00, 0x14, 0xde, 0xad};
    uint8_t buf[128];
    struct ue_rls_message msg;
    int len;

    len = ue_rls_encode_pdu_transmission(buf, sizeof(buf),
                                         0x1122334455667788ULL,
                                         UE_RLS_PDU_TYPE_DATA,
                                         0x01020304u,
                                         7,
                                         payload, sizeof(payload));
    assert(len == (int)(UE_RLS_HEADER_SIZE + 13 + sizeof(payload)));
    assert(buf[4] == UE_RLS_PDU_TRANSMISSION);
    assert(buf[13] == UE_RLS_PDU_TYPE_DATA);
    assert(be32(buf + 14) == 0x01020304u);
    assert(be32(buf + 18) == 7u);
    assert(be32(buf + 22) == sizeof(payload));
    assert(!memcmp(buf + 26, payload, sizeof(payload)));

    assert(ue_rls_decode(buf, (size_t)len, &msg) == 0);
    assert(msg.type == UE_RLS_PDU_TRANSMISSION);
    assert(msg.u.pdu_tx.sti == 0x1122334455667788ULL);
    assert(msg.u.pdu_tx.pdu_type == UE_RLS_PDU_TYPE_DATA);
    assert(msg.u.pdu_tx.pdu_id == 0x01020304u);
    assert(msg.u.pdu_tx.payload == 7u);
    assert(msg.u.pdu_tx.pdu_len == sizeof(payload));
    assert(!memcmp(msg.u.pdu_tx.pdu, payload, sizeof(payload)));
}

static void test_ack_roundtrip(void)
{
    uint32_t ids[] = {1, 0x11223344u, 0xffffffffu};
    uint8_t buf[64];
    struct ue_rls_message msg;
    int len;

    len = ue_rls_encode_pdu_ack(buf, sizeof(buf), 0x77, ids, 3);
    assert(len == (int)(UE_RLS_HEADER_SIZE + 4 + 3 * 4));
    assert(buf[4] == UE_RLS_PDU_TRANSMISSION_ACK);
    assert(be32(buf + 13) == 3u);

    assert(ue_rls_decode(buf, (size_t)len, &msg) == 0);
    assert(msg.type == UE_RLS_PDU_TRANSMISSION_ACK);
    assert(msg.u.pdu_ack.count == 3);
    assert(msg.u.pdu_ack.pdu_ids[0] == ids[0]);
    assert(msg.u.pdu_ack.pdu_ids[1] == ids[1]);
    assert(msg.u.pdu_ack.pdu_ids[2] == ids[2]);
}

static void test_decode_rejects_bad_inputs(void)
{
    uint8_t buf[64];
    struct ue_rls_message msg;
    int len;

    len = ue_rls_encode_heartbeat(buf, sizeof(buf), 1, 0, 0, 0);
    assert(len > 0);
    assert(ue_rls_decode(buf, 12, &msg) < 0);
    buf[0] = 0xff;
    assert(ue_rls_decode(buf, (size_t)len, &msg) < 0);
    buf[0] = UE_RLS_COMPAT_MARKER;
    buf[1] = 0xff;
    assert(ue_rls_decode(buf, (size_t)len, &msg) < 0);

    len = ue_rls_encode_pdu_transmission(buf, sizeof(buf), 1,
                                         UE_RLS_PDU_TYPE_DATA, 0, 1,
                                         (const uint8_t *)"abc", 3);
    assert(len > 0);
    buf[13] = 9;
    assert(ue_rls_decode(buf, (size_t)len, &msg) < 0);
}

int main(void)
{
    test_heartbeat_roundtrip();
    test_data_pdu_roundtrip();
    test_ack_roundtrip();
    test_decode_rejects_bad_inputs();
    return 0;
}
