/*
 * ue_rrc.c - Minimal RRC UPER codec for UE↔gNB NAS transport.
 *
 * Hand-coded ASN.1 UPER for the exact RRC messages needed.
 * Reference: 3GPP TS 38.331, UERANSIM asn1c-generated code.
 *
 * UPER bit layouts derived from ASN.1 definitions:
 *
 * UL-DCCH-Message:
 *   1 bit: c1 vs messageClassExtension (0=c1)
 *   4 bits: c1 choice index (0..15)
 *
 * ULInformationTransfer (c1 index 7):
 *   1 bit: criticalExtensions (0=ulInformationTransfer)
 *   1 bit: dedicatedNAS-Message present? (OPTIONAL in SEQUENCE, bitmap)
 *   0 bits: no extension marker content (we don't set ext)
 *   Then: length-determinant + NAS bytes
 *
 * DL-DCCH-Message:
 *   1 bit: c1 vs messageClassExtension (0=c1)
 *   4 bits: c1 choice index (0..15)
 *
 * DLInformationTransfer (c1 index 5):
 *   2 bits: rrc-TransactionIdentifier (INTEGER 0..3)
 *   1 bit: criticalExtensions (0=dlInformationTransfer)
 *   1 bit: dedicatedNAS-Message present?
 *   Then: length-determinant + NAS bytes
 *
 * RRCSetupRequest (UL-CCCH-Message):
 *   1 bit: c1 vs messageClassExtension (0=c1)
 *   2 bits: c1 choice index (0..3 in UL-CCCH, rrcSetupRequest=1)
 *   WAIT - UL-CCCH c1 has 4 items → 2 bits
 *   RRCSetupRequest:
 *     RRCSetupRequest-IEs:
 *       1 bit: ue-Identity choice (0=ng-5G-S-TMSI-Part1, 1=randomValue)
 *       39 bits: ue-Identity value (BIT STRING(SIZE(39)))
 *       4 bits: establishmentCause (ENUMERATED, 16 values)
 *       1 bit: spare (BIT STRING(SIZE(1)))
 *
 * UL-CCCH-Message ::= SEQUENCE {
 *   message UL-CCCH-MessageType
 * }
 * UL-CCCH-MessageType ::= CHOICE {
 *   c1 CHOICE { -- 4 items, 2 bits
 *     rrcSetupRequest(0), rrcResumeRequest(1),
 *     rrcReestablishmentRequest(2), rrcSystemInfoRequest(3)
 *   },
 *   messageClassExtension SEQUENCE {}
 * }
 * → Actually rrcSetupRequest is index 0 in the CHOICE.
 *
 * DL-CCCH-Message ::= SEQUENCE {
 *   message DL-CCCH-MessageType
 * }
 * DL-CCCH-MessageType ::= CHOICE {
 *   c1 CHOICE { -- 4 items, 2 bits
 *     rrcReject(0), rrcSetup(1),
 *     spare2(2), spare1(3)
 *   },
 *   messageClassExtension SEQUENCE {}
 * }
 * → rrcSetup is index 1.
 *
 * RRCSetup ::= SEQUENCE {
 *   rrc-TransactionIdentifier INTEGER(0..3),   -- 2 bits
 *   criticalExtensions CHOICE {
 *     rrcSetup RRCSetup-IEs,                   -- 0
 *     criticalExtensionsFuture SEQUENCE {}      -- 1
 *   }
 * }
 * RRCSetup-IEs ::= SEQUENCE {
 *   radioBearerConfig  RadioBearerConfig,
 *   masterCellGroup    OCTET STRING,
 *   lateNonCriticalExtension OCTET STRING OPTIONAL,
 *   nonCriticalExtension SEQUENCE {} OPTIONAL
 * }
 *
 * For RRCSetup decode, we only need to recognize the message and extract
 * rrc-TransactionIdentifier. We don't need the RadioBearerConfig/masterCellGroup
 * contents — they configure L2 which we don't implement.
 *
 * RRCSetupComplete (UL-DCCH c1 index 4):
 *   UL-DCCH header: 1 bit (c1) + 4 bits (index 4)
 *   RRCSetupComplete:
 *     2 bits: rrc-TransactionIdentifier (0..3)
 *     1 bit: criticalExtensions choice (0=rrcSetupComplete)
 *     RRCSetupComplete-IEs:
 *       3 bits: selectedPLMN-Identity INTEGER(1..12) → constrained (0..11)
 *       Optional field bitmap...
 *       Then: dedicatedNAS-Message (OCTET STRING, mandatory)
 */

#include "ue_rrc.h"

#include <string.h>

#include "../common/log.h"

/* ================================================================
 * Bitstream writer
 * ================================================================ */

void ue_rrc_bw_init(struct ue_rrc_bitwriter *bw, uint8_t *buf, size_t len)
{
    bw->buf = buf;
    bw->buf_len = len;
    bw->bit_pos = 0;
    if (buf && len > 0)
        memset(buf, 0, len);
}

int ue_rrc_bw_put_bits(struct ue_rrc_bitwriter *bw, uint64_t val, int nbits)
{
    int i;

    if (nbits <= 0 || nbits > 64)
        return -1;

    for (i = nbits - 1; i >= 0; i--) {
        size_t byte_idx = bw->bit_pos / 8;
        int bit_idx = 7 - (int)(bw->bit_pos % 8);

        if (byte_idx >= bw->buf_len)
            return -1;

        if ((val >> i) & 1)
            bw->buf[byte_idx] |= (uint8_t)(1 << bit_idx);

        bw->bit_pos++;
    }
    return 0;
}

int ue_rrc_bw_put_bytes(struct ue_rrc_bitwriter *bw, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (ue_rrc_bw_put_bits(bw, data[i], 8) < 0)
            return -1;
    }
    return 0;
}

size_t ue_rrc_bw_byte_len(const struct ue_rrc_bitwriter *bw)
{
    return (bw->bit_pos + 7) / 8;
}

/* ================================================================
 * Bitstream reader
 * ================================================================ */

void ue_rrc_br_init(struct ue_rrc_bitreader *br, const uint8_t *buf, size_t len)
{
    br->buf = buf;
    br->buf_len = len;
    br->bit_pos = 0;
}

int ue_rrc_br_get_bits(struct ue_rrc_bitreader *br, int nbits, uint64_t *val)
{
    uint64_t result = 0;
    int i;

    if (nbits <= 0 || nbits > 64 || !val)
        return -1;

    for (i = 0; i < nbits; i++) {
        size_t byte_idx = br->bit_pos / 8;
        int bit_idx = 7 - (int)(br->bit_pos % 8);

        if (byte_idx >= br->buf_len)
            return -1;

        result = (result << 1) | ((br->buf[byte_idx] >> bit_idx) & 1);
        br->bit_pos++;
    }

    *val = result;
    return 0;
}

int ue_rrc_br_get_bytes(struct ue_rrc_bitreader *br, uint8_t *out, size_t len)
{
    size_t i;
    uint64_t byte_val;

    for (i = 0; i < len; i++) {
        if (ue_rrc_br_get_bits(br, 8, &byte_val) < 0)
            return -1;
        out[i] = (uint8_t)byte_val;
    }
    return 0;
}

size_t ue_rrc_br_remaining_bits(const struct ue_rrc_bitreader *br)
{
    size_t total = br->buf_len * 8;
    if (br->bit_pos >= total)
        return 0;
    return total - br->bit_pos;
}

/* ================================================================
 * UPER length determinant helpers
 *
 * ASN.1 UPER length determinant for unconstrained lengths
 * (used for OCTET STRING without size constraint):
 *   If len < 128:    0 + 7-bit length (1 byte)
 *   If len < 16384:  10 + 14-bit length (2 bytes)
 *   Otherwise:       fragmented (not supported, NAS PDUs < 16384)
 * ================================================================ */

static int uper_put_length(struct ue_rrc_bitwriter *bw, size_t len)
{
    if (len < 128) {
        return ue_rrc_bw_put_bits(bw, len, 8);  /* 0xxxxxxx */
    }
    if (len < 16384) {
        /* 10xxxxxxxxxxxxxx */
        return ue_rrc_bw_put_bits(bw, 0x8000 | (uint64_t)len, 16);
    }
    return -1;  /* fragmented not supported */
}

static int uper_get_length(struct ue_rrc_bitreader *br, size_t *len)
{
    uint64_t first_byte;

    if (ue_rrc_br_get_bits(br, 8, &first_byte) < 0)
        return -1;

    if ((first_byte & 0x80) == 0) {
        *len = (size_t)first_byte;
        return 0;
    }

    /* Two-byte form: 10xxxxxx xxxxxxxx */
    if ((first_byte & 0xC0) == 0x80) {
        uint64_t second_byte;
        if (ue_rrc_br_get_bits(br, 8, &second_byte) < 0)
            return -1;
        *len = (size_t)(((first_byte & 0x3F) << 8) | second_byte);
        return 0;
    }

    return -1;  /* fragmented */
}

/* ================================================================
 * Encode: ULInformationTransfer
 *
 * UL-DCCH-Message:
 *   1 bit: 0 (c1)
 *   4 bits: 0111 (index 7 = ulInformationTransfer)
 *   ULInformationTransfer:
 *     1 bit: 0 (critExts = ulInformationTransfer, not future)
 *     ULInformationTransfer-IEs (SEQUENCE with extension marker):
 *       1 bit: 0 (no extension)
 *       1 bit: 1 (dedicatedNAS-Message is present)
 *       OCTET STRING: length determinant + bytes
 * ================================================================ */

int ue_rrc_encode_ul_info_transfer(uint8_t *buf, size_t buf_len,
                                   const uint8_t *nas_pdu, size_t nas_len)
{
    struct ue_rrc_bitwriter bw;

    if (!buf || !nas_pdu || nas_len == 0 || nas_len > UE_RRC_MAX_NAS_SIZE)
        return -1;

    ue_rrc_bw_init(&bw, buf, buf_len);

    /* UL-DCCH-MessageType: c1 (0) */
    if (ue_rrc_bw_put_bits(&bw, 0, 1) < 0) return -1;
    /* c1 choice index 7 = ulInformationTransfer */
    if (ue_rrc_bw_put_bits(&bw, 7, 4) < 0) return -1;

    /* ULInformationTransfer: criticalExtensions = ulInformationTransfer (0) */
    if (ue_rrc_bw_put_bits(&bw, 0, 1) < 0) return -1;

    /*
     * ULInformationTransfer-IEs optional bitmap (3 root optional fields):
     *   bit0 dedicatedNAS-Message present = 1
     *   bit1 lateNonCriticalExtension present = 0
     *   bit2 nonCriticalExtension present = 0
     */
    if (ue_rrc_bw_put_bits(&bw, 0b100, 3) < 0) return -1;

    /* dedicatedNAS-Message: OCTET STRING (unconstrained) */
    if (uper_put_length(&bw, nas_len) < 0) return -1;
    if (ue_rrc_bw_put_bytes(&bw, nas_pdu, nas_len) < 0) return -1;

    return (int)ue_rrc_bw_byte_len(&bw);
}

/* ================================================================
 * Encode: RRCSetupRequest
 *
 * UL-CCCH-Message:
 *   1 bit: 0 (c1)
 *   2 bits: 00 (index 0 = rrcSetupRequest)
 *   RRCSetupRequest:
 *     RRCSetupRequest-IEs:
 *       1 bit: ue-Identity CHOICE (0=ng-5G-S-TMSI-Part1, 1=randomValue)
 *       39 bits: value (BIT STRING SIZE(39))
 *       4 bits: establishmentCause (ENUMERATED, 16 values → 4 bits)
 *       1 bit: spare (BIT STRING SIZE(1))
 * ================================================================ */

int ue_rrc_encode_setup_request(uint8_t *buf, size_t buf_len,
                                uint64_t ue_identity,
                                uint8_t establishment_cause)
{
    struct ue_rrc_bitwriter bw;

    if (!buf)
        return -1;

    ue_rrc_bw_init(&bw, buf, buf_len);

    /* UL-CCCH-MessageType: c1 (0) */
    if (ue_rrc_bw_put_bits(&bw, 0, 1) < 0) return -1;
    /* c1 index 0 = rrcSetupRequest */
    if (ue_rrc_bw_put_bits(&bw, 0, 2) < 0) return -1;

    /* RRCSetupRequest-IEs */
    /* ue-Identity: randomValue (choice index 1) */
    if (ue_rrc_bw_put_bits(&bw, 1, 1) < 0) return -1;
    /* randomValue: BIT STRING SIZE(39) */
    if (ue_rrc_bw_put_bits(&bw, ue_identity & 0x7FFFFFFFFFULL, 39) < 0) return -1;
    /* establishmentCause: 4 bits */
    if (ue_rrc_bw_put_bits(&bw, establishment_cause & 0x0F, 4) < 0) return -1;
    /* spare: BIT STRING SIZE(1) = 0 */
    if (ue_rrc_bw_put_bits(&bw, 0, 1) < 0) return -1;

    return (int)ue_rrc_bw_byte_len(&bw);
}

/* ================================================================
 * Encode: RRCSetupComplete
 *
 * UL-DCCH-Message:
 *   1 bit: 0 (c1)
 *   4 bits: 0100 (index 4 = rrcSetupComplete)
 *   RRCSetupComplete:
 *     2 bits: rrc-TransactionIdentifier (0..3)
 *     1 bit: criticalExtensions (0 = rrcSetupComplete)
 *     RRCSetupComplete-IEs (SEQUENCE with extension marker):
 *       1 bit: 0 (no extension)
 *       3 bits: optional field bitmap (lateNonCriticalExtension,
 *               ng-5G-S-TMSI-Value, nonCriticalExtension) = 000
 *       4 bits: selectedPLMN-Identity INTEGER(1..12) → constrained (0..11)
 *       registeredAMF: absent (bit in bitmap = 0, handled above)
 *       dedicatedNAS-Message: OCTET STRING (mandatory)
 * ================================================================ */

int ue_rrc_encode_setup_complete(uint8_t *buf, size_t buf_len,
                                 uint8_t rrc_transaction_id,
                                 uint32_t selected_plmn_id,
                                 const uint8_t *nas_pdu, size_t nas_len)
{
    struct ue_rrc_bitwriter bw;
    uint32_t plmn_val;

    if (!buf || !nas_pdu || nas_len == 0 || nas_len > UE_RRC_MAX_NAS_SIZE)
        return -1;
    if (selected_plmn_id < 1 || selected_plmn_id > 12)
        return -1;

    ue_rrc_bw_init(&bw, buf, buf_len);

    /* UL-DCCH-MessageType: c1 (0) */
    if (ue_rrc_bw_put_bits(&bw, 0, 1) < 0) return -1;
    /* c1 index 2 = rrcSetupComplete (ASN.1 TS 38.331 order: measurementReport=0, rrcReconfComp=1, rrcSetupComp=2) */
    if (ue_rrc_bw_put_bits(&bw, 2, 4) < 0) return -1;

    /* rrc-TransactionIdentifier: INTEGER(0..3) */
    if (ue_rrc_bw_put_bits(&bw, rrc_transaction_id & 0x03, 2) < 0) return -1;

    /* criticalExtensions: rrcSetupComplete (0) */
    if (ue_rrc_bw_put_bits(&bw, 0, 1) < 0) return -1;

    /*
     * RRCSetupComplete-IEs (no extension marker in ASN.1):
     * Optional bitmap: 6 bits for optional IEs before dedicatedNAS-Message.
     *   bit 0: registeredAMF absent
     *   bit 1: guami-Type absent
     *   bit 2: s-NSSAI-List absent
     *   bit 3: ng-5G-S-TMSI-Value absent
     *   bit 4: lateNonCriticalExtension absent
     *   bit 5: nonCriticalExtension absent
     */
    if (ue_rrc_bw_put_bits(&bw, 0, 6) < 0) return -1;

    /* selectedPLMN-Identity: INTEGER(1..12) → encode as (value - 1) in 4 bits */
    plmn_val = selected_plmn_id - 1;
    if (ue_rrc_bw_put_bits(&bw, plmn_val, 4) < 0) return -1;

    /* registeredAMF: OPTIONAL, absent (covered by bitmap above) */
    /* guami-Type: OPTIONAL with default, absent */
    /* s-NSSAI-List: OPTIONAL, absent */

    /* dedicatedNAS-Message: OCTET STRING (mandatory, unconstrained) */
    if (uper_put_length(&bw, nas_len) < 0) return -1;
    if (ue_rrc_bw_put_bytes(&bw, nas_pdu, nas_len) < 0) return -1;

    LOG_DBG(RRC, "RRCSetupComplete encoded %d bytes: tx_id=%u plmn_id=%u nas_len=%zu",
            (int)ue_rrc_bw_byte_len(&bw), rrc_transaction_id, selected_plmn_id, nas_len);

    return (int)ue_rrc_bw_byte_len(&bw);
}

/* ================================================================
 * Decode: DL-DCCH-Message
 *
 * Handles:
 *   - DLInformationTransfer (c1 index 5): extract NAS PDU
 *   - RRCSetup (c1 index 3): extract transaction ID only
 * ================================================================ */

static int decode_dl_info_transfer(struct ue_rrc_bitreader *br,
                                   struct ue_rrc_message *out,
                                   const uint8_t *raw_buf)
{
    uint64_t val;
    uint64_t opt_bitmap;
    size_t nas_len;
    static uint8_t nas_copy_buf[UE_RRC_MAX_NAS_SIZE];

    out->type = UE_RRC_DL_INFO_TRANSFER;
    LOG_DBG(RRC, "DLInfoTransfer decode start: pdu_len=%zu bit_pos=%zu", br->buf_len, br->bit_pos);

    /* rrc-TransactionIdentifier: INTEGER(0..3), 2 bits */
    if (ue_rrc_br_get_bits(br, 2, &val) < 0) return -1;
    out->rrc_transaction_id = (uint8_t)val;
    LOG_DBG(RRC, "DLInfoTransfer tx_id=%u", out->rrc_transaction_id);

    /* criticalExtensions: CHOICE (0=dlInformationTransfer, 1=future) */
    if (ue_rrc_br_get_bits(br, 1, &val) < 0) return -1;
    LOG_DBG(RRC, "DLInfoTransfer criticalExtensions=%llu", (unsigned long long)val);
    if (val != 0) {
        LOG_WRN(RRC, "DLInfoTransfer unsupported criticalExtensions=%llu", (unsigned long long)val);
        return -1;
    }

    /*
     * DLInformationTransfer-IEs has 3 root optional fields and no root
     * extension marker in this ASN.1 version. Read full optional bitmap:
     *   bit0 dedicatedNAS-Message
     *   bit1 lateNonCriticalExtension
     *   bit2 nonCriticalExtension
     */
    if (ue_rrc_br_get_bits(br, 3, &opt_bitmap) < 0) return -1;
    LOG_DBG(RRC, "DLInformationTransfer opt_bitmap=0x%01llx", (unsigned long long)opt_bitmap);

    if ((opt_bitmap & 0b100) == 0) {
        /* No NAS PDU */
        out->nas_pdu = NULL;
        out->nas_len = 0;
        return 0;
    }

    /* dedicatedNAS-Message: OCTET STRING */
    if (uper_get_length(br, &nas_len) < 0) {
        LOG_WRN(RRC, "DLInfoTransfer NAS length decode failed at bit_pos=%zu", br->bit_pos);
        return -1;
    }
    if (nas_len > UE_RRC_MAX_NAS_SIZE) {
        LOG_WRN(RRC, "DLInfoTransfer NAS too large len=%zu max=%u", nas_len, (unsigned)UE_RRC_MAX_NAS_SIZE);
        return -1;
    }
    LOG_DBG(RRC, "DLInfoTransfer dedicatedNAS present len=%zu bit_pos=%zu", nas_len, br->bit_pos);

    /*
     * The NAS bytes start at the current bit position.
     * Since UPER OCTET STRING is byte-aligned only when the length determinant
     * makes it so — in practice our bit position after the length determinant
     * is byte-aligned. But we need to read via the bitreader to be safe.
     */
    out->nas_len = (uint32_t)nas_len;
    /* Point into the raw buffer at the current byte position */
    if (br->bit_pos % 8 == 0) {
        size_t byte_off = br->bit_pos / 8;
        if (byte_off + nas_len > br->buf_len) {
            LOG_WRN(RRC, "DLInfoTransfer aligned NAS out-of-bounds off=%zu len=%zu buf=%zu",
                    byte_off, nas_len, br->buf_len);
            return -1;
        }
        out->nas_pdu = raw_buf + byte_off;
        br->bit_pos += nas_len * 8;
        LOG_DBG(RRC, "DLInfoTransfer NAS extraction mode=aligned off=%zu", byte_off);
    } else {
        size_t i;
        uint64_t b;
        LOG_DBG(RRC, "DLInfoTransfer NAS extraction mode=unaligned-copy bit_pos=%zu", br->bit_pos);
        for (i = 0; i < nas_len; i++) {
            if (ue_rrc_br_get_bits(br, 8, &b) < 0) {
                LOG_WRN(RRC, "DLInfoTransfer unaligned NAS read failed at i=%zu", i);
                return -1;
            }
            nas_copy_buf[i] = (uint8_t)b;
        }
        out->nas_pdu = nas_copy_buf;
    }

    LOG_DBG(RRC, "DLInfoTransfer decode success nas_len=%u end_bit_pos=%zu",
            out->nas_len, br->bit_pos);

    return 0;
}

int ue_rrc_decode_dl_dcch(const uint8_t *data, size_t len,
                          struct ue_rrc_message *out)
{
    struct ue_rrc_bitreader br;
    uint64_t val;
    uint64_t c1_index;

    if (!data || len < 1 || !out)
        return -1;

    memset(out, 0, sizeof(*out));
    ue_rrc_br_init(&br, data, len);
    LOG_DBG(RRC, "DL-DCCH container decode start: pdu_len=%zu", len);

    /* DL-DCCH-MessageType: CHOICE (0=c1, 1=messageClassExtension) */
    if (ue_rrc_br_get_bits(&br, 1, &val) < 0) return -1;
    if (val != 0) return -1;  /* only c1 supported */

    /* c1: CHOICE of 16, 4 bits */
    if (ue_rrc_br_get_bits(&br, 4, &c1_index) < 0) return -1;
    LOG_DBG(RRC, "DL-DCCH container c1_index=%llu", (unsigned long long)c1_index);

    /*
     * DL-DCCH-MessageType c1 indices (TS 38.331):
     *   0 rrcReconfiguration, 1 rrcResume, 2 rrcRelease, 3 rrcReestablishment,
     *   4 securityModeCommand, 5 dlInformationTransfer, ...
     * RRCSetup is NOT in DL-DCCH (it is carried on DL-CCCH, see
     * ue_rrc_decode_dl_ccch). Only dlInformationTransfer is handled here; the
     * NAS-bearing message we need post-connection.
     */
    switch (c1_index) {
    case 5:  /* dlInformationTransfer */
        return decode_dl_info_transfer(&br, out, data);

    default:
        out->type = UE_RRC_UNKNOWN;
        return -1;
    }
}

/* ================================================================
 * Decode: DL-CCCH-Message
 *
 * DL-CCCH-MessageType ::= CHOICE {
 *   c1 CHOICE { -- 4 items, 2 bits
 *     rrcReject(0), rrcSetup(1), spare2(2), spare1(3)
 *   },
 *   messageClassExtension SEQUENCE {}
 * }
 * ================================================================ */

int ue_rrc_decode_dl_ccch(const uint8_t *data, size_t len,
                          struct ue_rrc_message *out)
{
    struct ue_rrc_bitreader br;
    uint64_t val;
    uint64_t c1_index;

    if (!data || len < 1 || !out)
        return -1;

    memset(out, 0, sizeof(*out));
    ue_rrc_br_init(&br, data, len);

    /* DL-CCCH-MessageType: CHOICE (0=c1, 1=messageClassExtension) */
    if (ue_rrc_br_get_bits(&br, 1, &val) < 0) return -1;
    if (val != 0) return -1;

    /* c1: CHOICE of 4, 2 bits */
    if (ue_rrc_br_get_bits(&br, 2, &c1_index) < 0) return -1;

    switch (c1_index) {
    case 1:  /* rrcSetup */
        out->type = UE_RRC_SETUP;
        /* rrc-TransactionIdentifier: INTEGER(0..3), 2 bits */
        if (ue_rrc_br_get_bits(&br, 2, &val) < 0) return -1;
        out->rrc_transaction_id = (uint8_t)val;
        /* Don't decode further — just need txId for RRCSetupComplete */
        return 0;

    case 0:  /* rrcReject */
        out->type = UE_RRC_UNKNOWN;
        return -1;

    default:
        out->type = UE_RRC_UNKNOWN;
        return -1;
    }
}
