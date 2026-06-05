#ifndef UE_NAS_DECODE_H
#define UE_NAS_DECODE_H

/*
 * ue_nas_decode - Minimal NAS PDU type recognition and field extraction.
 *
 * This is NOT a full NAS decoder. It recognizes the message type from
 * the raw wire bytes and extracts the minimum fields needed to drive
 * the ue_mm and ue_sm state machines.
 *
 * UERANSIM anchor:
 *   - src/lib/nas/enums.hpp     : EMessageType values
 *   - src/lib/nas/encode.cpp    : wire format
 *   - src/ue/nas/mm/sap.cpp     : NAS message dispatch
 *   - src/ue/nas/mm/transport.cpp : DL NAS TRANSPORT → SM message extraction
 *
 * NAS wire format (5G NAS, TS 24.501):
 *   MM messages (EPD=0x7E):
 *     Byte 0: EPD (0x7E)
 *     Byte 1: Security Header Type
 *     Byte 2: Message Type
 *     Byte 3+: IEs
 *
 *   SM messages (EPD=0x2E):
 *     Byte 0: EPD (0x2E)
 *     Byte 1: PDU Session Identity
 *     Byte 2: Procedure Transaction Identity
 *     Byte 3: Message Type
 *     Byte 4+: IEs
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Extended Protocol Discriminator values */
#define NAS_EPD_5GMM  0x7E
#define NAS_EPD_5GSM  0x2E

/* Security Header Types */
#define NAS_SHT_NOT_PROTECTED                       0x00
#define NAS_SHT_INTEGRITY_PROTECTED                 0x01
#define NAS_SHT_INTEGRITY_PROTECTED_CIPHERED        0x02
#define NAS_SHT_INTEGRITY_PROTECTED_NEW_CTX         0x03
#define NAS_SHT_INTEGRITY_PROTECTED_CIPHERED_NEW_CTX 0x04

/* 5GMM Message Types */
#define NAS_MSG_REGISTRATION_REQUEST          0x41
#define NAS_MSG_REGISTRATION_ACCEPT           0x42
#define NAS_MSG_REGISTRATION_COMPLETE         0x43
#define NAS_MSG_REGISTRATION_REJECT           0x44
#define NAS_MSG_DEREGISTRATION_REQUEST_UE     0x45
#define NAS_MSG_AUTHENTICATION_REQUEST        0x56
#define NAS_MSG_AUTHENTICATION_RESPONSE       0x57
#define NAS_MSG_AUTHENTICATION_REJECT         0x58
#define NAS_MSG_AUTHENTICATION_FAILURE        0x59
#define NAS_MSG_SECURITY_MODE_COMMAND         0x5D
#define NAS_MSG_SECURITY_MODE_COMPLETE        0x5E
#define NAS_MSG_DL_NAS_TRANSPORT              0x68
#define NAS_MSG_IDENTITY_REQUEST              0x5B
#define NAS_MSG_CONFIGURATION_UPDATE_COMMAND  0x54
#define NAS_MSG_CONFIGURATION_UPDATE_COMPLETE 0x55

/* 5GSM Message Types */
#define NAS_MSG_PDU_SESSION_EST_REQUEST       0xC1
#define NAS_MSG_PDU_SESSION_EST_ACCEPT        0xC2
#define NAS_MSG_PDU_SESSION_EST_REJECT        0xC3
#define NAS_MSG_PDU_SESSION_RELEASE_REQUEST   0xD1
#define NAS_MSG_PDU_SESSION_RELEASE_COMMAND   0xD3
#define NAS_MSG_PDU_SESSION_RELEASE_COMPLETE  0xD4
#define NAS_MSG_FIVEG_SM_STATUS               0xD6

/* 5GSM cause values (TS 24.501 §9.11.4.2) */
#define NAS_5GSM_CAUSE_INVALID_PTI            0x51  /* 81 */
#define NAS_5GSM_CAUSE_MSG_TYPE_NOT_IMPL      0x61  /* 97 */
#define NAS_5GSM_CAUSE_MSG_INCOMPAT_STATE     0x62  /* 98 */

/*
 * Recognized NAS event type (what the engine needs to know).
 */
enum ue_nas_event_type {
    UE_NAS_EVENT_UNKNOWN = 0,
    UE_NAS_EVENT_REGISTRATION_ACCEPT,
    UE_NAS_EVENT_REGISTRATION_REJECT,
    UE_NAS_EVENT_PDU_SESSION_EST_ACCEPT,
    UE_NAS_EVENT_PDU_SESSION_EST_REJECT,
    UE_NAS_EVENT_PDU_SESSION_RELEASE_CMD,
    UE_NAS_EVENT_AUTHENTICATION_REQUEST,
    UE_NAS_EVENT_SECURITY_MODE_COMMAND,
    UE_NAS_EVENT_IDENTITY_REQUEST,
    UE_NAS_EVENT_CONFIG_UPDATE_COMMAND,
    UE_NAS_EVENT_DL_NAS_TRANSPORT,
};

/*
 * Extracted fields from a recognized NAS message.
 */
struct ue_nas_event {
    enum ue_nas_event_type type;

    /* MM fields (Registration Accept/Reject) */
    uint8_t mm_cause;            /* 5GMM cause value (Reject) */
    bool has_guti;               /* 5G-GUTI present in Registration Accept */
    uint8_t guti[16];            /* raw 5GS mobile identity value (GUTI) */
    size_t guti_len;             /* length of guti[] */
    bool has_t3512;              /* T3512 periodic timer present (Reg. Accept) */
    uint32_t t3512_seconds;      /* T3512 value in seconds (0 = deactivated) */

    /* SM fields (PDU Session Accept/Reject/Release) */
    uint8_t psi;                 /* PDU Session Identity (0-15) */
    uint8_t pti;                 /* Procedure Transaction Identity */
    uint8_t sm_cause;            /* 5GSM cause value (Reject) */

    /* PDU Session Accept: extracted IP address */
    bool has_pdu_address;
    uint8_t pdu_addr_type;       /* 1=IPv4, 2=IPv6, 3=IPv4v6 */
    uint8_t ipv4_addr[4];

    /* PDU Session Accept: DNS server IPv4 from Extended PCO (container 0x000D) */
    bool has_dns;
    uint8_t dns_ipv4[4];

    /* PDU Session Accept: P-CSCF IPv4 from Extended PCO (container 0x000C) */
    bool has_pcscf;
    uint8_t pcscf_ipv4[4];

    /* Inner SM message from DL_NAS_TRANSPORT */
    bool has_inner_sm;
    const uint8_t *inner_sm_data;
    uint32_t inner_sm_len;

    /* Raw message type byte for debugging */
    uint8_t raw_msg_type;
    uint8_t raw_epd;

    /* Authentication Request extraction */
    bool has_auth_rand;
    bool has_auth_autn;
    bool has_auth_abba;
    uint8_t auth_abba_len;
    uint8_t auth_abba[16];
    uint8_t auth_rand[16];
    uint8_t auth_autn[16];

    /* Security Mode Command extraction */
    bool has_sec_algs;
    uint8_t sec_enc_alg;
    uint8_t sec_int_alg;
    bool has_ngksi;
    uint8_t ngksi;
    bool has_additional_5g_sec_info;
    uint8_t additional_5g_sec_info;

    /* Configuration Update Command: acknowledgement requested flag. */
    bool config_update_ack_requested;
};

/*
 * Recognize and extract fields from a raw NAS PDU.
 *
 * This handles:
 *   - Plain (unprotected) NAS messages
 *   - Security-protected NAS messages (skips MAC+SQN, reads inner plain)
 *   - DL_NAS_TRANSPORT wrapping SM messages
 *
 * NOTE: Security-protected messages require decryption for full processing.
 * Currently, this function attempts to read the inner plain message assuming
 * it is NOT encrypted (integrity-only protection). Full NAS security will
 * be implemented when the security context is established.
 *
 * Returns 0 on success (event populated), -1 if unrecognized.
 */
int ue_nas_decode_event(const uint8_t *pdu, size_t len,
                        struct ue_nas_event *event);

/*
 * Decode an SM message from DL_NAS_TRANSPORT payload container.
 * Called after ue_nas_decode_event returns UE_NAS_EVENT_DL_NAS_TRANSPORT.
 *
 * Returns 0 on success, -1 if the inner message is not recognized.
 */
int ue_nas_decode_inner_sm(const uint8_t *sm_pdu, size_t len,
                           struct ue_nas_event *event);

#endif
