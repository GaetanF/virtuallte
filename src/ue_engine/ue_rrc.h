#ifndef UE_RRC_H
#define UE_RRC_H

/*
 * ue_rrc - Minimal RRC UPER codec for UE↔gNB NAS transport.
 *
 * Hand-coded ASN.1 UPER encode/decode for exactly the RRC messages
 * needed by the real UE engine. NOT a generic ASN.1 library.
 *
 * UERANSIM anchor:
 *   - src/asn/rrc/ASN_RRC_UL-DCCH-Message.h
 *   - src/asn/rrc/ASN_RRC_DL-DCCH-Message.h
 *   - src/asn/rrc/ASN_RRC_ULInformationTransfer.h
 *   - src/asn/rrc/ASN_RRC_DLInformationTransfer.h
 *   - src/asn/rrc/ASN_RRC_RRCSetupRequest.h
 *   - src/asn/rrc/ASN_RRC_RRCSetup.h
 *   - src/asn/rrc/ASN_RRC_RRCSetupComplete.h
 *
 * RRC wire format (ASN.1 UPER, TS 38.331):
 *
 * UL-DCCH-Message ::= SEQUENCE {
 *   message  UL-DCCH-MessageType
 * }
 * UL-DCCH-MessageType ::= CHOICE {
 *   c1  CHOICE { -- 16 items, 4 bits
 *     ...
 *     rrcSetupComplete(4)    RRCSetupComplete,
 *     ...
 *     ulInformationTransfer(7) ULInformationTransfer,
 *     ...
 *   },
 *   messageClassExtension SEQUENCE {}
 * }
 *
 * DL-DCCH-Message ::= SEQUENCE {
 *   message  DL-DCCH-MessageType
 * }
 * DL-DCCH-MessageType ::= CHOICE {
 *   c1  CHOICE { -- 16 items, 4 bits
 *     ...
 *     dlInformationTransfer(5) DLInformationTransfer,
 *     ...
 *     rrcSetup(3)              RRCSetup,
 *     ...
 *   },
 *   messageClassExtension SEQUENCE {}
 * }
 *
 * ULInformationTransfer ::= SEQUENCE {
 *   criticalExtensions CHOICE {
 *     ulInformationTransfer ULInformationTransfer-IEs,
 *     ...
 *   }
 * }
 * ULInformationTransfer-IEs ::= SEQUENCE {
 *   dedicatedNAS-Message DedicatedNAS-Message OPTIONAL,
 *   ...
 * }
 * DedicatedNAS-Message ::= OCTET STRING
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Maximum NAS message size carried inside RRC.
 */
#define UE_RRC_MAX_NAS_SIZE  8192

/*
 * RRC message types we handle.
 */
enum ue_rrc_msg_type {
    UE_RRC_UNKNOWN = 0,
    UE_RRC_UL_INFO_TRANSFER,      /* UL-DCCH: ULInformationTransfer */
    UE_RRC_DL_INFO_TRANSFER,      /* DL-DCCH: DLInformationTransfer */
    UE_RRC_SETUP_REQUEST,          /* UL-CCCH: RRCSetupRequest */
    UE_RRC_SETUP,                  /* DL-CCCH: RRCSetup */
    UE_RRC_SETUP_COMPLETE,         /* UL-DCCH: RRCSetupComplete */
};

/*
 * Decoded RRC message.
 */
struct ue_rrc_message {
    enum ue_rrc_msg_type type;

    /* NAS payload (ULInfoTransfer, DLInfoTransfer, RRCSetupComplete) */
    const uint8_t *nas_pdu;       /* points into decode buffer */
    uint32_t nas_len;

    /* RRC transaction ID (DLInformationTransfer, RRCSetup) */
    uint8_t rrc_transaction_id;

    /* RRCSetupRequest fields */
    uint64_t ue_identity;         /* randomValue (39 bits) or ng-5G-S-TMSI-Part1 */
    uint8_t establishment_cause;  /* 4 bits, EstablishmentCause enum */
};

/*
 * UPER bitstream writer.
 */
struct ue_rrc_bitwriter {
    uint8_t *buf;
    size_t buf_len;
    size_t bit_pos;
};

/*
 * UPER bitstream reader.
 */
struct ue_rrc_bitreader {
    const uint8_t *buf;
    size_t buf_len;
    size_t bit_pos;
};

/* --- Bitstream primitives --- */

void ue_rrc_bw_init(struct ue_rrc_bitwriter *bw, uint8_t *buf, size_t len);
int  ue_rrc_bw_put_bits(struct ue_rrc_bitwriter *bw, uint64_t val, int nbits);
int  ue_rrc_bw_put_bytes(struct ue_rrc_bitwriter *bw, const uint8_t *data, size_t len);
size_t ue_rrc_bw_byte_len(const struct ue_rrc_bitwriter *bw);

void ue_rrc_br_init(struct ue_rrc_bitreader *br, const uint8_t *buf, size_t len);
int  ue_rrc_br_get_bits(struct ue_rrc_bitreader *br, int nbits, uint64_t *val);
int  ue_rrc_br_get_bytes(struct ue_rrc_bitreader *br, uint8_t *out, size_t len);
size_t ue_rrc_br_remaining_bits(const struct ue_rrc_bitreader *br);

/* --- RRC encode --- */

/*
 * Encode ULInformationTransfer wrapping a NAS PDU.
 * Output: UL-DCCH-Message in UPER.
 * Returns encoded byte count, or -1 on error.
 */
int ue_rrc_encode_ul_info_transfer(uint8_t *buf, size_t buf_len,
                                   const uint8_t *nas_pdu, size_t nas_len);

/*
 * Encode RRCSetupRequest.
 * Output: UL-CCCH-Message in UPER.
 * Returns encoded byte count, or -1 on error.
 */
int ue_rrc_encode_setup_request(uint8_t *buf, size_t buf_len,
                                uint64_t ue_identity,
                                uint8_t establishment_cause);

/*
 * Encode RRCSetupComplete carrying initial NAS PDU.
 * Output: UL-DCCH-Message in UPER.
 * Returns encoded byte count, or -1 on error.
 */
int ue_rrc_encode_setup_complete(uint8_t *buf, size_t buf_len,
                                 uint8_t rrc_transaction_id,
                                 uint32_t selected_plmn_id,
                                 const uint8_t *nas_pdu, size_t nas_len);

/* --- RRC decode --- */

/*
 * Decode a DL-DCCH-Message (UPER).
 * Handles DLInformationTransfer and RRCSetup.
 * Returns 0 on success, -1 on error.
 */
int ue_rrc_decode_dl_dcch(const uint8_t *data, size_t len,
                          struct ue_rrc_message *out);

/*
 * Decode a DL-CCCH-Message (UPER) — for RRCSetup from SRB0.
 * Returns 0 on success, -1 on error.
 */
int ue_rrc_decode_dl_ccch(const uint8_t *data, size_t len,
                          struct ue_rrc_message *out);

#endif
