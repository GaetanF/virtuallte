/*
 * ue_nas_encode.c - NAS uplink message encoder.
 *
 * UERANSIM anchor:
 *   - src/lib/nas/encode.cpp
 *   - src/ue/nas/mm/register.cpp
 *   - src/ue/nas/mm/auth.cpp
 *   - src/ue/nas/mm/security.cpp
 *   - src/ue/nas/mm/identity.cpp
 *   - src/ue/nas/sm/establishment.cpp
 *
 * Wire format: TS 24.501
 */

#include "ue_nas_encode.h"
#include "ue_nas_decode.h"   /* for NAS_EPD_*, NAS_MSG_* constants */

#include <string.h>

#include "../common/log.h"

/*
 * BCD encode helper: pack two decimal digits into one byte.
 * Digit a goes to lower nibble, digit b goes to upper nibble.
 * If digit is -1 (filler), use 0xF.
 */
static uint8_t bcd_pack(int a, int b)
{
    uint8_t lo = (a >= 0) ? (uint8_t)(a & 0x0F) : 0x0F;
    uint8_t hi = (b >= 0) ? (uint8_t)(b & 0x0F) : 0x0F;
    return (uint8_t)((hi << 4) | lo);
}

static int digit_val(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    return -1;
}

/*
 * Validate a BCD byte where ALL nibbles must be 0-9 (strict).
 * Used for routing indicator and MSIN (digits only).
 */
static int bcd_validate_strict(uint8_t byte, const char *field_name)
{
    int lo = byte & 0x0F;
    int hi = (byte >> 4) & 0x0F;
    if (lo > 9 || hi > 9) {
        LOG_ERR(NAS, "BCD strict failed: field=%s byte=0x%02x nibbles=[%d,%d]",
                field_name, byte, hi, lo);
        return -1;
    }
    return 0;
}

/*
 * Validate PLMN BCD bytes (3GPP-aware).
 * Byte 2 (octet2) upper nibble = MNC3 digit: 0xF is legitimate filler
 * for a 2-digit MNC. All other nibbles must be 0-9.
 */
static int bcd_validate_plmn(const uint8_t *plmn)
{
    /* octet1: MCC2|MCC1 — strict digits */
    int lo1 = plmn[0] & 0x0F, hi1 = (plmn[0] >> 4) & 0x0F;
    if (lo1 > 9 || hi1 > 9) {
        LOG_ERR(NAS, "BCD PLMN octet1 invalid: 0x%02x nibbles=[%d,%d]", plmn[0], hi1, lo1);
        return -1;
    }
    /* octet2: MNC3|MCC3 — MNC3 (upper nibble) may be 0xF for 2-digit MNC */
    int lo2 = plmn[1] & 0x0F, hi2 = (plmn[1] >> 4) & 0x0F;
    if (lo2 > 9 || (hi2 > 9 && hi2 != 0xF)) {
        LOG_ERR(NAS, "BCD PLMN octet2 invalid: 0x%02x nibbles=[%d,%d]", plmn[1], hi2, lo2);
        return -1;
    }
    /* octet3: MNC2|MNC1 — strict digits */
    int lo3 = plmn[2] & 0x0F, hi3 = (plmn[2] >> 4) & 0x0F;
    if (lo3 > 9 || hi3 > 9) {
        LOG_ERR(NAS, "BCD PLMN octet3 invalid: 0x%02x nibbles=[%d,%d]", plmn[2], hi3, lo3);
        return -1;
    }
    return 0;
}

/*
 * Validate entire SUCI buffer with context-aware BCD checks.
 */
static int suci_validate_bcd(const uint8_t *suci, size_t suci_len)
{
    size_t i;

    /* PLMN: bytes 1-3 (3GPP-aware, allows F filler in MNC3) */
    if (bcd_validate_plmn(suci + 1) < 0) return -1;

    /* Routing indicator: bytes 4-5 (strict digits only) */
    if (bcd_validate_strict(suci[4], "routing-ind-1") < 0) return -1;
    if (bcd_validate_strict(suci[5], "routing-ind-2") < 0) return -1;

    /* MSIN: bytes 8+ (strict digits, no filler in encoded output) */
    for (i = 8; i < suci_len; i++) {
        if (bcd_validate_strict(suci[i], "MSIN") < 0) return -1;
    }

    LOG_DBG(NAS, "  SUCI BCD validation OK (plmn+routing+msin)");
    return 0;
}

/*
 * Encode SUCI (5GS Mobile Identity for SUPI type IMSI, null scheme).
 *
 * TS 24.501 §9.11.3.4, Figure 9.11.3.4.1:
 *   Octet 1: SUPI format(3 bits) | Identity type(3 bits) = 0b000 | 0b0001
 *            Lower nibble of MCC digit 1 in bits 5-8
 *            → Actually: octet 1 = (MCC1 << 4) | (SUPI_format << 4 & 0x70) | type
 *
 * Simplified layout (from UERANSIM NasHelper::IE5gsMobileIdentity):
 *   Byte 0: Identity type=SUCI(1) | SUPI format=IMSI(0) → 0x01
 *            Actually bit layout: [spare:1][SUPI_fmt:3][odd/even:1][type:3]
 *            For SUCI: type=0b001, SUPI_fmt=0b000, odd/even depends on MSIN length
 *   Byte 1-2: MCC+MNC in BCD (same as EPS/LTE)
 *            Byte 1: MCC digit 2 | MCC digit 1
 *            Byte 2: MNC digit 3 | MCC digit 3
 *            Byte 3: MNC digit 2 | MNC digit 1
 *   Byte 3-4: Routing indicator BCD = 0x00 0x00 (not configured, digits only)
 *   Byte 5: Protection scheme id = 0x00 (null scheme)
 *   Byte 6: Home network public key identifier = 0x00
 *   Byte 7+: Scheme output = MSIN in BCD
 *
 * Wait, the actual format from 24.501 Figure 9.11.3.4.1:
 *   Octet 1: [MCC digit 2(4b) | MCC digit 1(4b)]  — but first we have the type
 *
 * Let me follow UERANSIM exactly. In UERANSIM (src/lib/nas/ie4.cpp,
 * IESuciMobileIdentity encode):
 *   Byte 0: (identity type & 0x07) | (SUPI format << 4)
 *           identity type = SUCI = 1
 *           SUPI format = IMSI = 0
 *           → 0x01
 *   Bytes 1-3: MCC/MNC BCD (standard 3GPP encoding)
 *     Byte 1: MCC2 << 4 | MCC1
 *     Byte 2: MNC3 << 4 | MCC3  (MNC3 = 0xF if 2-digit MNC)
 *     Byte 3: MNC2 << 4 | MNC1
 *   Bytes 4-5: Routing indicator BCD = 0x00 0x00 (not configured, must be valid BCD digits)
 *   Byte 6: Protection scheme = 0x00
 *   Byte 7: HN public key id = 0x00
 *   Bytes 8+: MSIN in BCD
 */
int ue_nas_encode_suci(uint8_t *buf, size_t buf_len,
                       const char *imsi,
                       const char *mcc,
                       const char *mnc)
{
    size_t imsi_len, mcc_len, mnc_len, msin_start, msin_len;
    size_t pos = 0;
    size_t i;
    int mcc1, mcc2, mcc3, mnc1, mnc2, mnc3;

    if (!buf || !imsi || !mcc || !mnc)
        return -1;

    imsi_len = strlen(imsi);
    mcc_len = strlen(mcc);
    mnc_len = strlen(mnc);

    if (mcc_len != 3 || (mnc_len != 2 && mnc_len != 3))
        return -1;
    if (imsi_len < mcc_len + mnc_len)
        return -1;

    msin_start = mcc_len + mnc_len;
    msin_len = imsi_len - msin_start;

    /* Need at least: 1 (type) + 3 (PLMN) + 2 (routing) + 1 (scheme) + 1 (keyid) + ceil(msin_len/2) */
    {
        size_t need = 8 + (msin_len + 1) / 2;
        if (buf_len < need)
            return -1;
    }

    mcc1 = digit_val(mcc[0]);
    mcc2 = digit_val(mcc[1]);
    mcc3 = digit_val(mcc[2]);
    mnc1 = digit_val(mnc[0]);
    mnc2 = digit_val(mnc[1]);
    mnc3 = (mnc_len == 3) ? digit_val(mnc[2]) : -1;  /* 0xF filler */

    /* Byte 0: identity type = SUCI(1), SUPI format = IMSI(0) */
    buf[pos++] = 0x01;

    /* Bytes 1-3: PLMN BCD */
    buf[pos++] = bcd_pack(mcc1, mcc2);
    buf[pos++] = bcd_pack(mcc3, mnc3);
    buf[pos++] = bcd_pack(mnc1, mnc2);

    /* Bytes 4-5: Routing indicator BCD.
     * Must be valid BCD digits (0-9), NOT 0xFF filler.
     * UERANSIM gNB decodes routing indicator as BCD string via
     * DecodeBcdString() and re-encodes via EncodeBcdString().
     * 0xFF is interpreted as filler nibble → '?' character →
     * EncodeBcdString throws "BCD string contains invalid characters".
     * Use "0000" (0x00 0x00) for "not configured" per TS 24.501. */
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;

    /* Byte 6: Protection scheme (null) */
    buf[pos++] = 0x00;

    /* Byte 7: Home network public key identifier */
    buf[pos++] = 0x00;

    /* Bytes 8+: MSIN in BCD */
    for (i = 0; i < msin_len; i += 2) {
        int d1 = digit_val(imsi[msin_start + i]);
        int d2 = (i + 1 < msin_len) ? digit_val(imsi[msin_start + i + 1]) : -1;
        buf[pos++] = bcd_pack(d1, d2);
    }

    /* SUCI BCD validation: ensure all nibbles are valid digits (0-9) */
    if (suci_validate_bcd(buf, pos) < 0) {
        LOG_ERR(NAS, "SUCI BCD validation FAILED — encoding rejected");
        return -1;
    }

    LOG_DBG(NAS, "SUCI encoded %zu bytes: type=0x%02x plmn=%02x%02x%02x "
                 "routing=%02x%02x scheme=0x%02x keyid=0x%02x msin_len=%zu",
            pos, buf[0], buf[1], buf[2], buf[3],
            buf[4], buf[5], buf[6], buf[7], msin_len);
    LOG_DBG(NAS, "  PLMN digits: MCC=%c%c%c MNC=%c%c%s",
            mcc[0], mcc[1], mcc[2], mnc[0], mnc[1],
            (mnc_len == 3) ? "" : "(2-digit)");
    LOG_DBG(NAS, "  routing indicator: 0x%02x%02x (BCD: %c%c%c%c)",
            buf[4], buf[5],
            '0' + ((buf[4] >> 4) & 0xF), '0' + (buf[4] & 0xF),
            '0' + ((buf[5] >> 4) & 0xF), '0' + (buf[5] & 0xF));
    LOG_DBG(NAS, "  SUCI BCD validation OK");

    return (int)pos;
}

/*
 * Registration Request (TS 24.501 §8.2.6)
 *
 * reg_type: 1=initial, 2=mobility update, 3=periodic update.
 * guti/guti_len: when non-NULL, the raw 5GS mobile identity value (a 5G-GUTI
 *                received in a prior Registration Accept) is replayed as the
 *                mobile identity. Otherwise a SUCI is built from imsi/mcc/mnc.
 *
 * UERANSIM anchor: register.cpp sendInitialRegistration/sendMobilityRegistration
 *   RegistrationRequest::onBuild order:
 *     ngKSI|regType, mobileIdentity, mmCapability(0x10), ueSecurityCapability(0x2E),
 *     requestedNSSAI(0x2F), updateType(0x53)
 *
 * initial_cleartext omits IEs Open5GS rejects in an unprotected InitialUEMessage.
 * requestedNSSAI is intentionally kept because the local gNB uses it for AMF
 * selection and strips it before forwarding the NAS PDU to Open5GS.
 */
int ue_nas_encode_registration_request(uint8_t *buf, size_t buf_len,
                                       const char *imsi,
                                       const char *mcc,
                                       const char *mnc,
                                       uint8_t slice_sst,
                                       uint8_t reg_type,
                                       const uint8_t *guti,
                                       size_t guti_len,
                                       uint8_t ngksi,
                                       int initial_cleartext)
{
    size_t pos = 0;
    uint8_t suci_buf[64];
    const uint8_t *mid;   /* mobile identity value */
    int mid_len;          /* mobile identity value length */

    if (!buf)
        return -1;
    if (reg_type < 1 || reg_type > 3)
        reg_type = 1;
    if (ngksi > 7)
        ngksi = 7;   /* 7 = no key available */

    if (guti && guti_len > 0) {
        mid = guti;
        mid_len = (int)guti_len;
    } else {
        mid_len = ue_nas_encode_suci(suci_buf, sizeof(suci_buf), imsi, mcc, mnc);
        if (mid_len < 0)
            return -1;
        mid = suci_buf;
    }

    /* header(4) + LV-E(2) + mid + mmCap(3) + secCap(4) + nssai(4) + updateType(3) */
    if (buf_len < 20 + (size_t)mid_len)
        return -1;

    /* EPD */
    buf[pos++] = NAS_EPD_5GMM;
    /* Security Header Type: not protected */
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    /* Message Type */
    buf[pos++] = NAS_MSG_REGISTRATION_REQUEST;

    /*
     * 5GS registration type (low nibble) + ngKSI (high nibble).
     *   low nibble:  bit4 = Follow-On Request (FOR) pending = 1
     *                bits1-3 = registration type (1/2/3)
     *   high nibble: ngKSI (0..6 = key set id, 7 = no key available), TSC native.
     * UERANSIM: IE5gsRegistrationType{FOR_PENDING, ...}; ngKSI from current ctx
     * or default ksi=7 when no security context.
     */
    buf[pos++] = (uint8_t)(((ngksi & 0x07) << 4) | 0x08 | (reg_type & 0x07));

    /* 5GS mobile identity (LV-E = 2-byte length + value) */
    buf[pos++] = (uint8_t)((mid_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(mid_len & 0xFF);
    memcpy(buf + pos, mid, (size_t)mid_len);
    pos += (size_t)mid_len;

    if (!initial_cleartext) {
        /*
         * 5G MM capability (IEI=0x10, TLV). TS 24.501 §9.11.3.1.
         * UERANSIM: s1Mode/hoAttach/lpp all NOT_SUPPORTED -> 0x00.
         */
        buf[pos++] = 0x10;
        buf[pos++] = 0x01;
        buf[pos++] = 0x00;
    }

    /*
     * UE security capability (IEI=0x2E, TLV). TS 24.501 §9.11.3.54.
     * Advertise only implemented algorithms:
     *   EA = 5G-EA0(0x80) + 5G-EA2(0x20) = 0xA0
     *   IA = 5G-IA0(0x80) + 5G-IA2(0x20) = 0xA0
     * SNOW3G (EA1/IA1) and ZUC (EA3/IA3) are not implemented, so not advertised.
     */
    buf[pos++] = 0x2E;
    buf[pos++] = 0x02;
    buf[pos++] = 0xA0;
    buf[pos++] = 0xA0;

    /*
     * requestedNSSAI (IEI=0x2F, TLV). One S-NSSAI entry (SST only):
     *   total len=2, entry_len=1, entry_value=<SST>. Omitted if slice_sst==0.
     */
    if (slice_sst > 0) {
        buf[pos++] = 0x2F;
        buf[pos++] = 0x02;
        buf[pos++] = 0x01;
        buf[pos++] = slice_sst;
    }

    /*
     * 5GS update type (IEI=0x53, TLV). TS 24.501 §9.11.3.9A.
     * UERANSIM: smsRequested=NOT_SUPPORTED, ngRanRcu=NOT_NEEDED -> 0x00.
     */
    if (!initial_cleartext) {
        buf[pos++] = 0x53;
        buf[pos++] = 0x01;
        buf[pos++] = 0x00;
    }

    LOG_DBG(NAS, "Registration Request: regType=%u ngKSI/regType=0x%02x mid_len=%d total=%zu (%s, %s)",
            reg_type, buf[3], mid_len, pos,
            (guti && guti_len > 0) ? "GUTI" : "SUCI",
            initial_cleartext ? "initial-cleartext" : "complete");
    if (slice_sst > 0)
        LOG_DBG(NAS, "  requestedNSSAI: SST=%u (encoded)", slice_sst);
    else
        LOG_DBG(NAS, "  requestedNSSAI: omitted (no slice configured)");

    return (int)pos;
}

/*
 * Registration Complete (TS 24.501 §8.2.39).
 * Plain message: EPD + SHT + MsgType(0x43). Sent integrity-protected by the
 * caller once a NAS security context is active. Optional SOR container omitted.
 */
int ue_nas_encode_registration_complete(uint8_t *buf, size_t buf_len)
{
    if (!buf || buf_len < 3)
        return -1;
    buf[0] = NAS_EPD_5GMM;
    buf[1] = NAS_SHT_NOT_PROTECTED;
    buf[2] = NAS_MSG_REGISTRATION_COMPLETE;
    return 3;
}

int ue_nas_encode_deregistration_request(uint8_t *buf, size_t buf_len,
                                         int switch_off,
                                         const uint8_t *guti, size_t guti_len,
                                         uint8_t ngksi)
{
    size_t pos = 0;

    if (!buf || !guti || guti_len == 0)
        return -1;
    if (ngksi > 7)
        ngksi = 7;
    /* header(3) + dereg-type/ngKSI(1) + 5GS mobile identity LV-E(2 + value) */
    if (buf_len < 6 + guti_len)
        return -1;

    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;   /* inner message; outer wrapper protects */
    buf[pos++] = NAS_MSG_DEREGISTRATION_REQUEST_UE;

    /*
     * De-registration type (low nibble) + ngKSI (high nibble), TS 24.501
     * §9.11.3.20:
     *   bits 1-2 = Access type (01 = 3GPP access)
     *   bit 3    = Re-registration required (0)
     *   bit 4    = Switch off (1 = switch off / power down)
     *   bits 5-8 = ngKSI (key set id, TSC native)
     */
    buf[pos++] = (uint8_t)(((ngksi & 0x07) << 4) |
                           (switch_off ? 0x08 : 0x00) | 0x01);

    /* 5GS mobile identity (LV-E): the stored 5G-GUTI value. */
    buf[pos++] = (uint8_t)((guti_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(guti_len & 0xFF);
    memcpy(buf + pos, guti, guti_len);
    pos += guti_len;

    return (int)pos;
}

/*
 * Configuration Update Complete (TS 24.501 §8.2.20). Plain, sent protected.
 */
int ue_nas_encode_configuration_update_complete(uint8_t *buf, size_t buf_len)
{
    if (!buf || buf_len < 3)
        return -1;
    buf[0] = NAS_EPD_5GMM;
    buf[1] = NAS_SHT_NOT_PROTECTED;
    buf[2] = NAS_MSG_CONFIGURATION_UPDATE_COMPLETE;
    return 3;
}

/*
 * Authentication Response (TS 24.501 §8.2.2)
 */
int ue_nas_encode_auth_response(uint8_t *buf, size_t buf_len,
                                const uint8_t *res, size_t res_len)
{
    size_t pos = 0;

    if (!buf || !res || res_len == 0 || res_len > 32)
        return -1;
    if (buf_len < 3 + 2 + res_len)
        return -1;

    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = NAS_MSG_AUTHENTICATION_RESPONSE;

    /* Authentication response parameter (IEI=0x2D, TLV) */
    buf[pos++] = 0x2D;              /* IEI */
    buf[pos++] = (uint8_t)res_len;  /* length */
    memcpy(buf + pos, res, res_len);
    pos += res_len;

    return (int)pos;
}

/*
 * Authentication Failure (TS 24.501 §8.2.4).
 *   EPD(0x7E) + SHT(0x00) + MsgType(0x59) + 5GMM cause (V, 1 byte)
 *   + optional Authentication failure parameter (IEI=0x30, TLV) carrying the
 *     AUTS resynchronisation token (14 bytes) when cause = synch failure.
 *
 * cause: 0x14 (20) MAC failure, 0x15 (21) synch failure.
 * auts/auts_len: AUTS for synch failure, or NULL/0 for MAC failure.
 */
int ue_nas_encode_auth_failure(uint8_t *buf, size_t buf_len, uint8_t cause,
                               const uint8_t *auts, size_t auts_len)
{
    size_t pos = 0;

    if (!buf || buf_len < 4)
        return -1;

    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = NAS_MSG_AUTHENTICATION_FAILURE;
    buf[pos++] = cause;             /* 5GMM cause (V) */

    if (auts && auts_len > 0) {
        if (pos + 2 + auts_len > buf_len)
            return -1;
        buf[pos++] = 0x30;                  /* Authentication failure parameter IEI */
        buf[pos++] = (uint8_t)auts_len;     /* length */
        memcpy(buf + pos, auts, auts_len);
        pos += auts_len;
    }

    return (int)pos;
}

/*
 * UL NAS Transport carrying a 5GSM STATUS (TS 24.501 §8.3.13).
 * Inner SM: EPD(0x2E) + PSI + PTI + MsgType(0xD6) + 5GSM cause (V, 1 byte).
 */
int ue_nas_encode_sm_status(uint8_t *buf, size_t buf_len,
                            uint8_t psi, uint8_t pti, uint8_t cause)
{
    size_t pos = 0;
    uint8_t sm_buf[8];
    int sm_len;
    size_t sm_pos = 0;

    if (!buf || buf_len < 16)
        return -1;

    /* Inner SM: 5GSM STATUS */
    sm_buf[sm_pos++] = NAS_EPD_5GSM;
    sm_buf[sm_pos++] = psi;
    sm_buf[sm_pos++] = pti;
    sm_buf[sm_pos++] = NAS_MSG_FIVEG_SM_STATUS;
    sm_buf[sm_pos++] = cause;
    sm_len = (int)sm_pos;

    /* UL NAS Transport wrapper */
    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = 0x67;  /* UL NAS Transport */
    buf[pos++] = 0x01;  /* payload container type: N1 SM */
    buf[pos++] = (uint8_t)((sm_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(sm_len & 0xFF);
    memcpy(buf + pos, sm_buf, (size_t)sm_len);
    pos += (size_t)sm_len;
    buf[pos++] = 0x12;  /* PDU Session ID */
    buf[pos++] = psi;

    return (int)pos;
}

/*
 * Security Mode Complete (TS 24.501 §8.2.26)
 */
int ue_nas_encode_security_mode_complete(uint8_t *buf, size_t buf_len,
                                         const uint8_t *nas_container,
                                         size_t nas_container_len)
{
    size_t pos = 0;

    if (!buf)
        return -1;
    if (buf_len < 3 + (nas_container ? (3 + nas_container_len) : 0))
        return -1;

    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = NAS_MSG_SECURITY_MODE_COMPLETE;

    /* Optional: NAS message container (IEI=0x71, TLV-E) */
    if (nas_container && nas_container_len > 0) {
        if (pos + 3 + nas_container_len > buf_len)
            return -1;
        buf[pos++] = 0x71;  /* IEI */
        buf[pos++] = (uint8_t)((nas_container_len >> 8) & 0xFF);
        buf[pos++] = (uint8_t)(nas_container_len & 0xFF);
        memcpy(buf + pos, nas_container, nas_container_len);
        pos += nas_container_len;
    }

    return (int)pos;
}

/*
 * Identity Response with SUCI (TS 24.501 §8.2.22)
 */
int ue_nas_encode_identity_response(uint8_t *buf, size_t buf_len,
                                    const char *imsi,
                                    const char *mcc,
                                    const char *mnc)
{
    size_t pos = 0;
    uint8_t suci_buf[64];
    int suci_len;

    if (!buf || buf_len < 16)
        return -1;

    suci_len = ue_nas_encode_suci(suci_buf, sizeof(suci_buf), imsi, mcc, mnc);
    if (suci_len < 0)
        return -1;

    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = 0x5C;  /* Identity Response */

    /* 5GS mobile identity: SUCI (LV-E) */
    if (pos + 2 + (size_t)suci_len > buf_len)
        return -1;
    buf[pos++] = (uint8_t)((suci_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(suci_len & 0xFF);
    memcpy(buf + pos, suci_buf, (size_t)suci_len);
    pos += (size_t)suci_len;

    return (int)pos;
}

/*
 * Build inner SM: PDU Session Establishment Request (TS 24.501 §8.3.1.1)
 *
 * UERANSIM anchor:
 *   - src/ue/nas/sm/establishment.cpp: sendEstablishmentRequest()
 *   - src/lib/nas/msg.cpp:338-348: PduSessionEstablishmentRequest::onBuild()
 *   - src/ue/nas/sm/transport.cpp:60-87: sendSmMessage()
 *
 * EPD(0x2E) + PSI + PTI + MsgType(0xC1)
 * + mandatory IntegrityProtectionMaximumDataRate (2 bytes)
 * + optional IE1 PDU Session Type (IEI=0x9, low nibble)
 * + optional IE1 SSC Mode (IEI=0xA, low nibble)
 * + optional TLV SM Capability (IEI=0x28)
 * + optional TLV-E Extended PCO (IEI=0x7B)
 */
static int encode_pdu_session_est_request_inner(uint8_t *buf, size_t buf_len,
                                                uint8_t psi,
                                                uint8_t pti,
                                                uint8_t pdu_session_type)
{
    size_t pos = 0;

    if (buf_len < 20)
        return -1;

    buf[pos++] = NAS_EPD_5GSM;
    buf[pos++] = psi;
    buf[pos++] = pti;
    buf[pos++] = NAS_MSG_PDU_SESSION_EST_REQUEST;

    /*
     * Mandatory: Integrity protection maximum data rate (2 bytes)
     * 0xFF = full data rate for both UL and DL
     */
    buf[pos++] = 0xFF;  /* UL */
    buf[pos++] = 0xFF;  /* DL */

    /* Optional IE1: PDU Session Type (IEI=0x9, low nibble) */
    buf[pos++] = (uint8_t)(0x90 | (pdu_session_type & 0x0F));

    /* Optional IE1: SSC Mode (IEI=0xA, low nibble) — SSC mode 1 */
    buf[pos++] = 0xA1;

    /* Optional TLV: SM Capability (IEI=0x28, len=1, value=0x00)
     * UERANSIM establishment.cpp:19-25, ie4.cpp:426-428
     * rqos=NOT_SUPPORTED(0), mh6pdu=NOT_SUPPORTED(0)
     */
    buf[pos++] = 0x28;
    buf[pos++] = 0x01;
    buf[pos++] = 0x00;

    /* Optional TLV-E: Extended PCO (IEI=0x7B, len=8)
     *
     * UERANSIM establishment.cpp:101-110, proto_conf.cpp:23-45.
     * Type 6 TLV: IEI(1) + Length(2 bytes) + Content.
     * EPCO header: 0x80 (configProtocol=PPP, extension=true).
     * Each container item: id(2) + len(1) + content. UERANSIM uses empty
     * content (len=0) for both items, matching byte-for-byte:
     *   Item 1: 0x000A (IP address allocation via NAS signalling), len=0
     *   Item 2: 0x000D (DNS server IPv4 address request), len=0
     *   Item 3: 0x000C (P-CSCF IPv4 address request), len=0 — needed for SMS
     *           over IMS; the network only returns P-CSCF when requested here.
     */
    buf[pos++] = 0x7B;

    size_t len_pos = pos;
    buf[pos++] = 0x00; /* length high byte placeholder */
    buf[pos++] = 0x00; /* length low byte placeholder */

    size_t content_start = pos;

    buf[pos++] = 0x80;
    buf[pos++] = 0x00;
    buf[pos++] = 0x0A;
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = 0x0D;
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = 0x0C;
    buf[pos++] = 0x00;

    size_t epco_len = pos - content_start;
    buf[len_pos]     = (epco_len >> 8) & 0xff;
    buf[len_pos + 1] = epco_len & 0xff;

    return (int)pos;
}

/*
 * UL NAS Transport carrying PDU Session Establishment Request.
 */
int ue_nas_encode_pdu_session_est_request(uint8_t *buf, size_t buf_len,
                                          uint8_t psi,
                                          uint8_t pti,
                                          uint8_t pdu_session_type,
                                          uint8_t request_type,
                                          const char *dnn,
                                          uint8_t s_nssai_sst)
{
    size_t pos = 0;
    uint8_t sm_buf[128];
    int sm_len;
    size_t dnn_len;

    if (!buf || buf_len < 32)
        return -1;

    /* Build inner SM message */
    sm_len = encode_pdu_session_est_request_inner(sm_buf, sizeof(sm_buf),
                                                  psi, pti, pdu_session_type);
    if (sm_len < 0)
        return -1;

    /* UL NAS Transport header */
    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = 0x67;  /* UL NAS Transport */

    /*
     * Payload container type (lower nibble) + spare (upper nibble)
     * 0x01 = N1 SM information
     */
    buf[pos++] = 0x01;

    /* Payload container length (2 bytes, big-endian) */
    buf[pos++] = (uint8_t)((sm_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(sm_len & 0xFF);

    /* Payload container (SM NAS message) */
    if (pos + (size_t)sm_len > buf_len)
        return -1;
    memcpy(buf + pos, sm_buf, (size_t)sm_len);
    pos += (size_t)sm_len;

    /* Optional IEI 0x12: PDU Session ID (TV, 1+1) */
    buf[pos++] = 0x12;
    buf[pos++] = psi;

    /* Optional IE1: Request Type (IEI=0x8, low nibble)
     * TS 24.501 §9.11.3.4: 1=initial, 2=existing, 4=initial emergency
     */
    if (request_type == 0)
        request_type = 1;
    buf[pos++] = (uint8_t)(0x80 | (request_type & 0x0F));

    /* Optional IEI 0x22: S-NSSAI (TLV) */
    if (s_nssai_sst > 0) {
        buf[pos++] = 0x22;  /* IEI */
        buf[pos++] = 0x01;  /* length = 1 (SST only) */
        buf[pos++] = s_nssai_sst;
    }

    /* Optional IEI 0x25: DNN (TLV) */
    if (dnn && dnn[0] != '\0') {
        dnn_len = strlen(dnn);
        if (dnn_len > 100) dnn_len = 100;
        if (pos + 3 + dnn_len > buf_len)
            return -1;
        buf[pos++] = 0x25;  /* IEI */
        /*
         * DNN encoding (TS 24.501 §9.11.2.1A):
         * Like DNS labels: length byte + label bytes.
         * For simple single-label DNN: 1 byte len + string.
         */
        buf[pos++] = (uint8_t)(dnn_len + 1);  /* IE length: label_len_byte + label */
        buf[pos++] = (uint8_t)dnn_len;         /* label length */
        memcpy(buf + pos, dnn, dnn_len);
        pos += dnn_len;
    }

    return (int)pos;
}

/*
 * UL NAS Transport carrying PDU Session Release Complete.
 */
int ue_nas_encode_pdu_session_release_complete(uint8_t *buf, size_t buf_len,
                                               uint8_t psi, uint8_t pti)
{
    size_t pos = 0;
    uint8_t sm_buf[8];
    int sm_len;
    size_t sm_pos = 0;

    if (!buf || buf_len < 16)
        return -1;

    /* Inner SM: PDU Session Release Complete (echo the PTI from the Command) */
    sm_buf[sm_pos++] = NAS_EPD_5GSM;
    sm_buf[sm_pos++] = psi;
    sm_buf[sm_pos++] = pti;
    sm_buf[sm_pos++] = NAS_MSG_PDU_SESSION_RELEASE_COMPLETE;
    sm_len = (int)sm_pos;

    /* UL NAS Transport wrapper */
    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = 0x67;  /* UL NAS Transport */

    /* Payload container type: N1 SM */
    buf[pos++] = 0x01;

    /* Payload container length */
    buf[pos++] = (uint8_t)((sm_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(sm_len & 0xFF);

    /* Payload container */
    memcpy(buf + pos, sm_buf, (size_t)sm_len);
    pos += (size_t)sm_len;

    /* PDU Session ID */
    buf[pos++] = 0x12;
    buf[pos++] = psi;

    return (int)pos;
}

/*
 * UL NAS Transport carrying PDU Session Release Request (UE-initiated release).
 *
 * UERANSIM anchor: src/ue/nas/sm/release.cpp sendReleaseRequest.
 * Inner SM (TS 24.501 §8.3.4): EPD(0x2E) + PSI + PTI + MsgType(0xD1).
 * Optional 5GSM cause / EPCO are omitted (network accepts the bare request).
 */
int ue_nas_encode_pdu_session_release_request(uint8_t *buf, size_t buf_len,
                                              uint8_t psi, uint8_t pti)
{
    size_t pos = 0;
    uint8_t sm_buf[8];
    int sm_len;
    size_t sm_pos = 0;

    if (!buf || buf_len < 16)
        return -1;

    /* Inner SM: PDU Session Release Request */
    sm_buf[sm_pos++] = NAS_EPD_5GSM;
    sm_buf[sm_pos++] = psi;
    sm_buf[sm_pos++] = pti ? pti : 1;       /* PTI: UE-allocated for this procedure */
    sm_buf[sm_pos++] = NAS_MSG_PDU_SESSION_RELEASE_REQUEST;
    /* 5GSM cause (type 3 TV, IEI 0x59) = REGULAR_DEACTIVATION (0x24), as UERANSIM. */
    sm_buf[sm_pos++] = 0x59;
    sm_buf[sm_pos++] = 0x24;
    sm_len = (int)sm_pos;

    /* UL NAS Transport wrapper */
    buf[pos++] = NAS_EPD_5GMM;
    buf[pos++] = NAS_SHT_NOT_PROTECTED;
    buf[pos++] = 0x67;  /* UL NAS Transport */

    /* Payload container type: N1 SM */
    buf[pos++] = 0x01;

    /* Payload container length */
    buf[pos++] = (uint8_t)((sm_len >> 8) & 0xFF);
    buf[pos++] = (uint8_t)(sm_len & 0xFF);

    /* Payload container */
    memcpy(buf + pos, sm_buf, (size_t)sm_len);
    pos += (size_t)sm_len;

    /* PDU Session ID */
    buf[pos++] = 0x12;
    buf[pos++] = psi;

    return (int)pos;
}
