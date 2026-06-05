/*
 * ue_nas_decode.c - Minimal NAS PDU recognition and field extraction.
 *
 * UERANSIM anchor:
 *   - src/lib/nas/encode.cpp    : NAS encode/decode
 *   - src/ue/nas/mm/messaging.cpp : receiveNasMessage dispatch
 *   - src/ue/nas/mm/transport.cpp : DL NAS TRANSPORT handling
 *   - src/lib/nas/ie4.cpp       : IE decode (PDU Address, etc.)
 *
 * This is intentionally minimal. We extract the message type and
 * the few IEs needed to drive ue_mm/ue_sm state machines.
 */

#include "ue_nas_decode.h"

#include <stdio.h>
#include <string.h>

#include "../common/log.h"

/*
 * Decode a GPRS Timer 3 value octet (TS 24.008 §10.5.7.4a) to seconds.
 * Returns 0 for the "deactivated" unit.
 */
static uint32_t gprs_timer3_seconds(uint8_t v)
{
    uint32_t value = v & 0x1F;
    switch ((v >> 5) & 0x07) {
    case 0: return value * 600u;      /* x 10 minutes */
    case 1: return value * 3600u;     /* x 1 hour */
    case 2: return value * 36000u;    /* x 10 hours */
    case 3: return value * 2u;        /* x 2 seconds */
    case 4: return value * 30u;       /* x 30 seconds */
    case 5: return value * 60u;       /* x 1 minute */
    case 6: return value * 1152000u;  /* x 320 hours */
    default: return 0;                /* deactivated */
    }
}

/*
 * Best-effort extraction of the T3512 value (GPRS Timer 3, IEI 0x5E, TLV with
 * length 1) from a Registration Accept. A full per-IEI NAS walk is not
 * implemented; we scan for the "0x5E 0x01 <octet>" signature after the
 * registration result. Bounds-checked, so a false match is harmless.
 */
static bool parse_t3512(const uint8_t *pdu, size_t len, uint32_t *out_seconds)
{
    size_t i;
    for (i = 5; i + 2 < len; i++) {
        if (pdu[i] == 0x5E && pdu[i + 1] == 0x01) {
            *out_seconds = gprs_timer3_seconds(pdu[i + 2]);
            return true;
        }
    }
    return false;
}

/*
 * Decode a plain 5GMM message (EPD=0x7E, SHT=0x00).
 * Minimum 3 bytes: EPD + SHT + MsgType
 */
static int decode_mm_message(const uint8_t *pdu, size_t len,
                               struct ue_nas_event *event)
{
    uint8_t msg_type;

    if (len < 3)
        return -1;
    if (pdu[0] != NAS_EPD_5GMM)
        return -1;

    /* pdu[1] = SHT, should be 0 for plain */
    msg_type = pdu[2];
    event->raw_msg_type = msg_type;
    event->raw_epd = NAS_EPD_5GMM;

    LOG_TRC(NAS, "decode MM msg_type=0x%02x len=%zu", msg_type, len);

    switch (msg_type) {
    case NAS_MSG_REGISTRATION_ACCEPT:
        event->type = UE_NAS_EVENT_REGISTRATION_ACCEPT;
        /*
         * Registration Accept (TS 24.501 §8.2.7):
         *   [3]   5GS registration result (mandatory, LV: len + value)
         *   then optional IEs. Per RegistrationAccept::onBuild, only the
         *   half-octet IEs 0x9/0xA/0xB may appear before the 5G-GUTI
         *   (5GS mobile identity, IEI=0x77, TLV-E = IEI + 2-byte len + value).
         *
         * We extract the 5G-GUTI so the UE can (a) acknowledge it with a
         * REGISTRATION COMPLETE and (b) replay it as the mobile identity in
         * later registrations.
         */
        if (len >= 5) {
            size_t pos = (size_t)4 + pdu[3];   /* skip 5GS registration result LV */

            /* Skip optional half-octet IEs (IEI in high nibble: 0x9/0xA/0xB). */
            while (pos < len) {
                uint8_t hi = (pdu[pos] >> 4) & 0x0F;
                if (hi == 0x9 || hi == 0xA || hi == 0xB) {
                    pos++;
                    continue;
                }
                break;
            }

            if (pos + 3 <= len && pdu[pos] == 0x77) {
                uint16_t glen = ((uint16_t)pdu[pos + 1] << 8) | pdu[pos + 2];
                /* Identity type lives in the low 3 bits of the first value
                 * octet; 5G-GUTI = type 2 (UERANSIM encodes 0xf2). */
                if (glen > 0 && glen <= sizeof(event->guti) &&
                    pos + 3 + glen <= len &&
                    (pdu[pos + 3] & 0x07) == 0x02) {
                    memcpy(event->guti, pdu + pos + 3, glen);
                    event->guti_len = glen;
                    event->has_guti = true;
                    LOG_DBG(NAS, "Registration Accept: 5G-GUTI present (%u bytes)",
                            (unsigned)glen);
                }
            }

            if (parse_t3512(pdu, len, &event->t3512_seconds)) {
                event->has_t3512 = true;
                LOG_DBG(NAS, "Registration Accept: T3512 = %u s",
                        event->t3512_seconds);
            }
        }
        return 0;

    case NAS_MSG_REGISTRATION_REJECT:
        event->type = UE_NAS_EVENT_REGISTRATION_REJECT;
        /*
         * Registration Reject (TS 24.501 §8.2.8):
         *   Byte 3: 5GMM cause (mandatory, V, 1 byte)
         */
        if (len >= 4)
            event->mm_cause = pdu[3];
        return 0;

    case NAS_MSG_AUTHENTICATION_REQUEST:
        event->type = UE_NAS_EVENT_AUTHENTICATION_REQUEST;
        /*
         * TS 24.501 §8.2.2 wire format (UERANSIM confirmed):
         *   Byte 3:  ngKSI (IE1 half-octet, 1 byte)
         *   Byte 4+: ABBA (IE4 LV mandatory, 1 byte length + N bytes value)
         *   Then:    RAND (IE3 TV, IEI=0x21 + 16 bytes raw, no length field)
         *   Then:    AUTN (IE4 TLV, IEI=0x20 + 1 byte length + 16 bytes value)
         */
        if (len >= 3 + 1 + 2 + 17 + 18) {
            size_t pos = 3;
            uint8_t abba_len;
            uint8_t ngksi;
            char abba_hex[256] = "";
            char rand_hex[64] = "";
            char autn_hex[64] = "";
            size_t k;
            int hp;

            ngksi = pdu[pos] & 0x07;
            event->ngksi = ngksi;
            event->has_ngksi = true;
            pos += 1; /* ngKSI (half-octet IE, 1 byte) */

            abba_len = pdu[pos];
            if (pos + 1 + abba_len <= len) {
                if (abba_len <= sizeof(event->auth_abba)) {
                    memcpy(event->auth_abba, pdu + pos + 1, abba_len);
                    event->auth_abba_len = abba_len;
                    event->has_auth_abba = true;
                }
                hp = 0;
                for (k = 0; k < abba_len && hp < (int)sizeof(abba_hex) - 3; k++)
                    hp += snprintf(abba_hex + hp, sizeof(abba_hex) - (size_t)hp,
                                   "%02x", pdu[pos + 1 + k]);
            }
            pos += 1 + abba_len; /* skip ABBA LV */

            /* RAND: IE3 TV = IEI(1) + Value(16), no length field */
            if (pos + 17 <= len && pdu[pos] == 0x21) {
                memcpy(event->auth_rand, pdu + pos + 1, 16);
                event->has_auth_rand = true;
                pos += 17;
            }

            /* AUTN: IE4 TLV = IEI(1) + Length(1) + Value(16) */
            if (pos + 18 <= len && pdu[pos] == 0x20 && pdu[pos + 1] == 16) {
                memcpy(event->auth_autn, pdu + pos + 2, 16);
                event->has_auth_autn = true;
            }

            hp = 0;
            for (k = 0; k < 16 && hp < (int)sizeof(rand_hex) - 3; k++)
                hp += snprintf(rand_hex + hp, sizeof(rand_hex) - (size_t)hp,
                               "%02x", event->auth_rand[k]);
            hp = 0;
            for (k = 0; k < 16 && hp < (int)sizeof(autn_hex) - 3; k++)
                hp += snprintf(autn_hex + hp, sizeof(autn_hex) - (size_t)hp,
                               "%02x", event->auth_autn[k]);

            LOG_DBG(NAS, "AuthenticationRequest: ngKSI=%u ABBA(len=%u)=%s",
                    ngksi, abba_len, abba_hex[0] ? abba_hex : "<empty>");
            LOG_TRC(NAS, "AuthenticationRequest: RAND=%s", rand_hex);
            LOG_TRC(NAS, "AuthenticationRequest: AUTN=%s", autn_hex);
        }
        return 0;

    case NAS_MSG_SECURITY_MODE_COMMAND:
        event->type = UE_NAS_EVENT_SECURITY_MODE_COMMAND;
        if (len >= 5) {
            uint8_t algs = pdu[3];
            uint8_t ngksi = pdu[4];
            size_t pos = 5;
            event->has_sec_algs = true;
            event->sec_enc_alg = (algs >> 4) & 0x0F;
            event->sec_int_alg = algs & 0x0F;
            event->has_ngksi = true;
            event->ngksi = ngksi & 0x07;

            while (pos + 2 <= len) {
                if (pdu[pos] == 0x36) {
                    uint8_t ie_len = pdu[pos + 1];
                    if (ie_len >= 1 && pos + 2 + ie_len <= len) {
                        event->has_additional_5g_sec_info = true;
                        event->additional_5g_sec_info = pdu[pos + 2];
                    }
                    break;
                }
                pos++;
            }

            LOG_DBG(NAS, "SMC: enc_alg=%u int_alg=%u ngKSI=%u",
                    event->sec_enc_alg, event->sec_int_alg, event->ngksi);
            if (event->has_additional_5g_sec_info)
                LOG_DBG(NAS, "SMC: additional5gSecInfo=0x%02x",
                        event->additional_5g_sec_info);
        }
        return 0;

    case NAS_MSG_IDENTITY_REQUEST:
        event->type = UE_NAS_EVENT_IDENTITY_REQUEST;
        return 0;

    case NAS_MSG_CONFIGURATION_UPDATE_COMMAND:
        event->type = UE_NAS_EVENT_CONFIG_UPDATE_COMMAND;
        /*
         * configurationUpdateIndication is the first optional IE (IE1, IEI in
         * high nibble = 0xD). Bit 1 of its value = acknowledgement requested.
         */
        if (len >= 4 && (pdu[3] >> 4) == 0x0D)
            event->config_update_ack_requested = (pdu[3] & 0x01) != 0;
        return 0;

    case NAS_MSG_DL_NAS_TRANSPORT:
        event->type = UE_NAS_EVENT_DL_NAS_TRANSPORT;
        /*
         * DL NAS TRANSPORT (TS 24.501 §8.2.11):
         *   Byte 3: Payload container type (4 bits, lower nibble)
         *   Byte 4: Payload container length (2 bytes, LE? Actually network byte order)
         *
         * Simplified: extract payload container.
         *   Byte 3: payload container type (full byte for our decode)
         *   Bytes 4-5: payload container length (16-bit)
         *   Bytes 6+: payload container (the SM NAS message)
         *
         * After the mandatory IEs, optional IEI 0x12 = PDU Session ID.
         *
         * For now, we use a simplified extraction:
         */
        if (len >= 6) {
            /* payload container type is in lower nibble of byte 3 */
            uint8_t pct = pdu[3] & 0x0F;
            if (pct == 0x01) {
                /* N1 SM information */
                uint16_t container_len = ((uint16_t)pdu[4] << 8) | pdu[5];
                if (container_len > 0 && len >= (size_t)container_len + 6) {
                    event->has_inner_sm = true;
                    event->inner_sm_data = pdu + 6;
                    event->inner_sm_len = container_len;
                }
            }

            /*
             * Scan for optional PDU Session ID IE (IEI = 0x12).
             * It's a TV IE: 1 byte IEI + 1 byte value.
             */
            {
                size_t pos = 6;
                if (event->has_inner_sm)
                    pos += event->inner_sm_len;
                while (pos + 1 < len) {
                    if (pdu[pos] == 0x12) {
                        event->psi = pdu[pos + 1];
                        break;
                    }
                    /* Skip unknown IEs - simplified, may not be perfect */
                    break;
                }
            }
        }
        return 0;

    default:
        event->type = UE_NAS_EVENT_UNKNOWN;
        return -1;
    }
}

/*
 * Extract the DNS server IPv4 address from an Extended PCO IE (IEI=0x7B) in a
 * PDU Session Establishment Accept.
 *
 * The full per-IEI NAS walk needed to reach 0x7B reliably is not implemented
 * here; instead we locate the ePCO by its signature (IEI 0x7B, a valid 2-byte
 * length, then the configuration-protocol octet 0x80) and then walk its
 * container items looking for id 0x000D (DNS server IPv4 address) with a
 * 4-byte value. All accesses are bounds-checked, so a false match is harmless.
 *
 * Returns true and fills out[4] on success.
 */
static bool parse_epco_container_ipv4(const uint8_t *pdu, size_t len,
                                      uint16_t wanted_id, uint8_t out[4])
{
    size_t i;

    for (i = 4; i + 4 < len; i++) {
        size_t epco_len, content_start, p, end;

        if (pdu[i] != 0x7B)
            continue;
        epco_len = ((size_t)pdu[i + 1] << 8) | pdu[i + 2];
        if (epco_len < 1 || i + 3 + epco_len > len)
            continue;
        if (pdu[i + 3] != 0x80)         /* ePCO config-protocol octet */
            continue;

        content_start = i + 4;          /* skip IEI(1) + len(2) + 0x80(1) */
        end = i + 3 + epco_len;
        p = content_start;

        /* Walk container items: id(2) + len(1) + content. */
        while (p + 3 <= end) {
            uint16_t id = ((uint16_t)pdu[p] << 8) | pdu[p + 1];
            uint8_t clen = pdu[p + 2];
            const uint8_t *cval = pdu + p + 3;

            if (p + 3 + clen > end)
                break;
            if (id == wanted_id && clen == 4) {
                memcpy(out, cval, 4);
                return true;
            }
            p += 3 + clen;
        }
    }
    return false;
}

static bool parse_epco_dns(const uint8_t *pdu, size_t len, uint8_t out[4])
{
    return parse_epco_container_ipv4(pdu, len, 0x000D, out);  /* DNS server IPv4 */
}

static bool parse_epco_pcscf(const uint8_t *pdu, size_t len, uint8_t out[4])
{
    return parse_epco_container_ipv4(pdu, len, 0x000C, out);  /* P-CSCF IPv4 */
}

/*
 * Decode a 5GSM message (EPD=0x2E).
 * Format: EPD(1) + PSI(1) + PTI(1) + MsgType(1) + IEs
 */
static int decode_sm_message(const uint8_t *pdu, size_t len,
                              struct ue_nas_event *event)
{
    uint8_t msg_type;

    if (len < 4)
        return -1;
    if (pdu[0] != NAS_EPD_5GSM)
        return -1;

    event->psi = pdu[1];
    event->pti = pdu[2];
    msg_type = pdu[3];
    event->raw_msg_type = msg_type;
    event->raw_epd = NAS_EPD_5GSM;

    switch (msg_type) {
    case NAS_MSG_PDU_SESSION_EST_ACCEPT:
        event->type = UE_NAS_EVENT_PDU_SESSION_EST_ACCEPT;
        /*
         * PDU Session Establishment Accept (TS 24.501 §8.3.2.1):
         *   Byte 4: Selected PDU session type + SSC mode (combined byte)
         *   Byte 5: Authorized QoS rules length (LV-E, 2 bytes length)
         *   ... then various optional IEs
         *
         * We need to find the PDU Address IE (IEI = 0x29, TLV):
         *   IEI(1) + Length(1) + Type(1) + Address(4 for IPv4)
         *
         * Simplified scan for PDU Address IE.
         */
        if (len >= 5) {
            /* Skip mandatory IEs to find PDU Address */
            size_t pos = 4;

            /* Byte 4: selected session type + SSC (1 byte) */
            pos++;

            /* Authorized QoS rules: LV-E (2 byte length prefix) */
            if (pos + 2 <= len) {
                uint16_t qos_len = ((uint16_t)pdu[pos] << 8) | pdu[pos + 1];
                pos += 2 + qos_len;
            }

            /* Session AMBR: LV (1 byte length prefix) */
            if (pos + 1 <= len) {
                uint8_t ambr_len = pdu[pos];
                pos += 1 + ambr_len;
            }

            /* Now scan optional IEs for PDU Address (IEI=0x29) */
            while (pos + 2 < len) {
                uint8_t iei = pdu[pos];
                if (iei == 0x29) {
                    /* PDU Address: TLV */
                    uint8_t addr_ie_len = pdu[pos + 1];
                    if (pos + 2 + addr_ie_len <= len && addr_ie_len >= 5) {
                        event->has_pdu_address = true;
                        event->pdu_addr_type = pdu[pos + 2];
                        if (event->pdu_addr_type == 1 && addr_ie_len >= 5) {
                            /* IPv4: type(1) + addr(4) */
                            memcpy(event->ipv4_addr, pdu + pos + 3, 4);
                        }
                    }
                    break;
                }

                /*
                 * Skip unknown TLV IE. IEI top nibble determines format:
                 *   If bit 7 set (>=0x80): TV format, 1 byte total for type 1
                 *   Otherwise: TLV format
                 */
                if (iei >= 0x80) {
                    pos += 1;  /* Type 1 TV: just the IEI byte */
                } else {
                    if (pos + 1 >= len) break;
                    uint8_t ie_len = pdu[pos + 1];
                    pos += 2 + ie_len;
                }
            }
        }

        /* Extract DNS server IPv4 from the Extended PCO, if present. */
        if (parse_epco_dns(pdu, len, event->dns_ipv4)) {
            event->has_dns = true;
            LOG_DBG(NAS, "PDU Session Accept: DNS IPv4 %u.%u.%u.%u",
                    event->dns_ipv4[0], event->dns_ipv4[1],
                    event->dns_ipv4[2], event->dns_ipv4[3]);
        }

        /* Extract P-CSCF IPv4 from the Extended PCO (SMS over IMS), if present. */
        if (parse_epco_pcscf(pdu, len, event->pcscf_ipv4)) {
            event->has_pcscf = true;
            LOG_DBG(NAS, "PDU Session Accept: P-CSCF IPv4 %u.%u.%u.%u",
                    event->pcscf_ipv4[0], event->pcscf_ipv4[1],
                    event->pcscf_ipv4[2], event->pcscf_ipv4[3]);
        }
        return 0;

    case NAS_MSG_PDU_SESSION_EST_REJECT:
        event->type = UE_NAS_EVENT_PDU_SESSION_EST_REJECT;
        /*
         * PDU Session Establishment Reject:
         *   Byte 4: 5GSM cause (mandatory, V, 1 byte)
         */
        if (len >= 5)
            event->sm_cause = pdu[4];
        return 0;

    case NAS_MSG_PDU_SESSION_RELEASE_COMMAND:
        event->type = UE_NAS_EVENT_PDU_SESSION_RELEASE_CMD;
        if (len >= 5)
            event->sm_cause = pdu[4];
        return 0;

    default:
        event->type = UE_NAS_EVENT_UNKNOWN;
        return -1;
    }
}

int ue_nas_decode_event(const uint8_t *pdu, size_t len,
                        struct ue_nas_event *event)
{
    if (!pdu || len < 2 || !event)
        return -1;

    memset(event, 0, sizeof(*event));
    event->type = UE_NAS_EVENT_UNKNOWN;

    if (pdu[0] == NAS_EPD_5GMM && pdu[1] != NAS_SHT_NOT_PROTECTED)
        return -1;

    /* Dispatch by EPD */
    if (pdu[0] == NAS_EPD_5GMM) {
        if (decode_mm_message(pdu, len, event) < 0)
            return -1;

        /* If DL_NAS_TRANSPORT, recursively decode inner SM */
        if (event->type == UE_NAS_EVENT_DL_NAS_TRANSPORT &&
            event->has_inner_sm) {
            return ue_nas_decode_inner_sm(event->inner_sm_data,
                                          event->inner_sm_len,
                                          event);
        }
        return 0;
    }

    if (pdu[0] == NAS_EPD_5GSM) {
        return decode_sm_message(pdu, len, event);
    }

    return -1;
}

int ue_nas_decode_inner_sm(const uint8_t *sm_pdu, size_t len,
                           struct ue_nas_event *event)
{
    if (!sm_pdu || len < 4 || !event)
        return -1;

    if (sm_pdu[0] != NAS_EPD_5GSM)
        return -1;

    return decode_sm_message(sm_pdu, len, event);
}
