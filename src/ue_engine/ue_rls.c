/*
 * ue_rls.c - RLS wire protocol encode/decode.
 *
 * Wire format is big-endian, matching UERANSIM exactly.
 * See UERANSIM src/lib/rls/rls_pdu.cpp for reference.
 */

#include "ue_rls.h"

#include <string.h>

/* Big-endian helpers */

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void put_be64(uint8_t *p, uint64_t v)
{
    put_be32(p, (uint32_t)(v >> 32));
    put_be32(p + 4, (uint32_t)(v));
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static int32_t get_be32_signed(const uint8_t *p)
{
    uint32_t u = get_be32(p);
    int32_t s;
    memcpy(&s, &u, sizeof(s));
    return s;
}

static uint64_t get_be64(const uint8_t *p)
{
    return ((uint64_t)get_be32(p) << 32) | (uint64_t)get_be32(p + 4);
}

/*
 * Write the common RLS header (13 bytes).
 */
static int rls_write_header(uint8_t *buf, size_t buf_len,
                            enum ue_rls_msg_type type, uint64_t sti)
{
    if (buf_len < UE_RLS_HEADER_SIZE)
        return -1;

    buf[0] = UE_RLS_COMPAT_MARKER;
    buf[1] = UE_RLS_VERSION_MAJOR;
    buf[2] = UE_RLS_VERSION_MINOR;
    buf[3] = UE_RLS_VERSION_PATCH;
    buf[4] = (uint8_t)type;
    put_be64(buf + 5, sti);

    return UE_RLS_HEADER_SIZE;
}

int ue_rls_encode_heartbeat(uint8_t *buf, size_t buf_len,
                            uint64_t sti,
                            int32_t x, int32_t y, int32_t z)
{
    /* Header (13) + simPos (3 x 4 = 12) = 25 bytes */
    size_t total = UE_RLS_HEADER_SIZE + 12;
    uint32_t ux, uy, uz;

    if (!buf || buf_len < total)
        return -1;

    rls_write_header(buf, buf_len, UE_RLS_HEARTBEAT, sti);

    memcpy(&ux, &x, sizeof(ux));
    memcpy(&uy, &y, sizeof(uy));
    memcpy(&uz, &z, sizeof(uz));
    put_be32(buf + 13, ux);
    put_be32(buf + 17, uy);
    put_be32(buf + 21, uz);

    return (int)total;
}

int ue_rls_encode_pdu_transmission(uint8_t *buf, size_t buf_len,
                                   uint64_t sti,
                                   enum ue_rls_pdu_type pdu_type,
                                   uint32_t pdu_id,
                                   uint32_t payload,
                                   const uint8_t *pdu, uint32_t pdu_len)
{
    /* Header (13) + pduType(1) + pduId(4) + payload(4) + pduLen(4) + pdu = 26 + pdu_len */
    size_t total = UE_RLS_HEADER_SIZE + 1 + 4 + 4 + 4 + pdu_len;

    if (!buf || buf_len < total)
        return -1;
    if (pdu_len > UE_RLS_MAX_PDU_SIZE)
        return -1;

    rls_write_header(buf, buf_len, UE_RLS_PDU_TRANSMISSION, sti);

    buf[13] = (uint8_t)pdu_type;
    put_be32(buf + 14, pdu_id);
    put_be32(buf + 18, payload);
    put_be32(buf + 22, pdu_len);

    if (pdu && pdu_len > 0)
        memcpy(buf + 26, pdu, pdu_len);

    return (int)total;
}

int ue_rls_encode_pdu_ack(uint8_t *buf, size_t buf_len,
                          uint64_t sti,
                          const uint32_t *pdu_ids, uint32_t count)
{
    size_t total = UE_RLS_HEADER_SIZE + 4 + (size_t)count * 4;
    uint32_t i;

    if (!buf || buf_len < total)
        return -1;

    rls_write_header(buf, buf_len, UE_RLS_PDU_TRANSMISSION_ACK, sti);

    put_be32(buf + 13, count);
    for (i = 0; i < count; i++)
        put_be32(buf + 17 + i * 4, pdu_ids[i]);

    return (int)total;
}

int ue_rls_decode(const uint8_t *data, size_t len,
                  struct ue_rls_message *out)
{
    uint8_t msg_type_byte;
    uint64_t sti;
    const uint8_t *p;
    size_t remaining;
    uint32_t pdu_len, count, i;

    if (!data || !out || len < UE_RLS_HEADER_SIZE)
        return -1;

    /* Check compatibility marker */
    if (data[0] != UE_RLS_COMPAT_MARKER)
        return -1;

    /* Check version */
    if (data[1] != UE_RLS_VERSION_MAJOR ||
        data[2] != UE_RLS_VERSION_MINOR ||
        data[3] != UE_RLS_VERSION_PATCH)
        return -1;

    msg_type_byte = data[4];
    sti = get_be64(data + 5);

    p = data + UE_RLS_HEADER_SIZE;
    remaining = len - UE_RLS_HEADER_SIZE;

    memset(out, 0, sizeof(*out));

    switch (msg_type_byte) {
    case UE_RLS_HEARTBEAT:
        if (remaining < 12)
            return -1;
        out->type = UE_RLS_HEARTBEAT;
        out->u.heartbeat.sti = sti;
        out->u.heartbeat.sim_pos_x = get_be32_signed(p);
        out->u.heartbeat.sim_pos_y = get_be32_signed(p + 4);
        out->u.heartbeat.sim_pos_z = get_be32_signed(p + 8);
        return 0;

    case UE_RLS_HEARTBEAT_ACK:
        if (remaining < 4)
            return -1;
        out->type = UE_RLS_HEARTBEAT_ACK;
        out->u.heartbeat_ack.sti = sti;
        out->u.heartbeat_ack.dbm = get_be32_signed(p);
        return 0;

    case UE_RLS_PDU_TRANSMISSION:
        if (remaining < 13)
            return -1;
        if (p[0] != UE_RLS_PDU_TYPE_RRC && p[0] != UE_RLS_PDU_TYPE_DATA)
            return -1;
        pdu_len = get_be32(p + 9);
        if (pdu_len > UE_RLS_MAX_PDU_SIZE)
            return -1;
        if (remaining < 13 + pdu_len)
            return -1;

        out->type = UE_RLS_PDU_TRANSMISSION;
        out->u.pdu_tx.sti = sti;
        out->u.pdu_tx.pdu_type = (enum ue_rls_pdu_type)p[0];
        out->u.pdu_tx.pdu_id = get_be32(p + 1);
        out->u.pdu_tx.payload = get_be32(p + 5);
        out->u.pdu_tx.pdu_len = pdu_len;
        out->u.pdu_tx.pdu = (pdu_len > 0) ? (p + 13) : NULL;
        return 0;

    case UE_RLS_PDU_TRANSMISSION_ACK:
        if (remaining < 4)
            return -1;
        count = get_be32(p);
        if (count > UE_RLS_MAX_ACK_IDS)
            return -1;
        if (remaining < 4 + (size_t)count * 4)
            return -1;

        out->type = UE_RLS_PDU_TRANSMISSION_ACK;
        out->u.pdu_ack.sti = sti;
        out->u.pdu_ack.count = count;
        for (i = 0; i < count; i++)
            out->u.pdu_ack.pdu_ids[i] = get_be32(p + 4 + i * 4);
        return 0;

    default:
        return -1;
    }
}
