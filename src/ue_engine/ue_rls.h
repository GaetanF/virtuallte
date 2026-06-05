#ifndef UE_RLS_H
#define UE_RLS_H

/*
 * ue_rls - RLS (Radio Link Simulation) wire protocol codec.
 *
 * Implements encode/decode for the UERANSIM RLS protocol used for
 * UE ↔ gNB communication over UDP.
 *
 * Wire format matches UERANSIM exactly (src/lib/rls/rls_pdu.cpp):
 *   Byte 0:     0x03 (compatibility marker)
 *   Bytes 1-3:  version (Major=3, Minor=2, Patch=8)
 *   Byte 4:     message type
 *   Bytes 5-12: STI (uint64, big-endian)
 *   Bytes 13+:  message-specific payload
 *
 * Message types:
 *   HEARTBEAT (4):       simPos.x/y/z (3 x int32)
 *   HEARTBEAT_ACK (5):   dbm (int32)
 *   PDU_TRANSMISSION (6): pduType(u8) + pduId(u32) + payload(u32) + pduLen(u32) + pdu
 *   PDU_TRANSMISSION_ACK (7): count(u32) + pduId[count] (u32 each)
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * UERANSIM version constants for RLS protocol.
 * Must match the gNB we connect to.
 */
#define UE_RLS_VERSION_MAJOR 3
#define UE_RLS_VERSION_MINOR 2
#define UE_RLS_VERSION_PATCH 8

#define UE_RLS_COMPAT_MARKER 0x03

/*
 * RLS header size: 1 (compat) + 3 (version) + 1 (msgType) + 8 (sti) = 13
 */
#define UE_RLS_HEADER_SIZE 13

/*
 * Maximum RLS PDU payload size.
 */
#define UE_RLS_MAX_PDU_SIZE 16384

enum ue_rls_msg_type {
    UE_RLS_HEARTBEAT            = 4,
    UE_RLS_HEARTBEAT_ACK        = 5,
    UE_RLS_PDU_TRANSMISSION     = 6,
    UE_RLS_PDU_TRANSMISSION_ACK = 7,
};

enum ue_rls_pdu_type {
    UE_RLS_PDU_TYPE_RRC  = 1,
    UE_RLS_PDU_TYPE_DATA = 2,
};

/*
 * Decoded RLS message structures.
 */
struct ue_rls_heartbeat {
    uint64_t sti;
    int32_t sim_pos_x;
    int32_t sim_pos_y;
    int32_t sim_pos_z;
};

struct ue_rls_heartbeat_ack {
    uint64_t sti;
    int32_t dbm;
};

struct ue_rls_pdu_transmission {
    uint64_t sti;
    enum ue_rls_pdu_type pdu_type;
    uint32_t pdu_id;
    uint32_t payload;    /* RRC channel for RRC, PSI for DATA */
    const uint8_t *pdu;  /* pointer into decode buffer, NOT owned */
    uint32_t pdu_len;
};

#define UE_RLS_MAX_ACK_IDS 64

struct ue_rls_pdu_transmission_ack {
    uint64_t sti;
    uint32_t pdu_ids[UE_RLS_MAX_ACK_IDS];
    uint32_t count;
};

/*
 * Generic decoded message (tagged union).
 */
struct ue_rls_message {
    enum ue_rls_msg_type type;
    union {
        struct ue_rls_heartbeat heartbeat;
        struct ue_rls_heartbeat_ack heartbeat_ack;
        struct ue_rls_pdu_transmission pdu_tx;
        struct ue_rls_pdu_transmission_ack pdu_ack;
    } u;
};

/*
 * Encode a HEARTBEAT message.
 * Returns number of bytes written to buf, or -1 on error.
 */
int ue_rls_encode_heartbeat(uint8_t *buf, size_t buf_len,
                            uint64_t sti,
                            int32_t x, int32_t y, int32_t z);

/*
 * Encode a PDU_TRANSMISSION message (RRC or DATA).
 * Returns number of bytes written to buf, or -1 on error.
 */
int ue_rls_encode_pdu_transmission(uint8_t *buf, size_t buf_len,
                                   uint64_t sti,
                                   enum ue_rls_pdu_type pdu_type,
                                   uint32_t pdu_id,
                                   uint32_t payload,
                                   const uint8_t *pdu, uint32_t pdu_len);

/*
 * Encode a PDU_TRANSMISSION_ACK message.
 * Returns number of bytes written to buf, or -1 on error.
 */
int ue_rls_encode_pdu_ack(uint8_t *buf, size_t buf_len,
                          uint64_t sti,
                          const uint32_t *pdu_ids, uint32_t count);

/*
 * Decode an RLS message from raw bytes.
 * The pdu pointer in pdu_tx points into data[] - valid only while data[] lives.
 * Returns 0 on success, -1 on decode error.
 */
int ue_rls_decode(const uint8_t *data, size_t len,
                  struct ue_rls_message *out);

#endif
