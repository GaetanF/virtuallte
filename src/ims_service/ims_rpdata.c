#include "ims_rpdata.h"

#include <string.h>

int ims_build_rp_data(const uint8_t *mbim_pdu, size_t mbim_len,
                      uint8_t rp_mr, uint8_t *out, size_t out_cap)
{
    size_t sca_len;      /* SCA value octets (TON/NPI + BCD); 0 = no SMSC */
    size_t sca_total;    /* SCA-len byte + value = SCA LV size */
    size_t tpdu_len;
    size_t pos = 0;

    if (!mbim_pdu || !out || mbim_len < 1)
        return -1;

    sca_len = mbim_pdu[0];
    sca_total = 1 + sca_len;
    if (sca_total >= mbim_len)              /* nothing left for the TPDU */
        return -1;
    tpdu_len = mbim_len - sca_total;
    if (tpdu_len == 0 || tpdu_len > 255)    /* RP-UD length is one octet */
        return -1;
    if (3 + (sca_len ? sca_total : 1) + 1 + tpdu_len > out_cap)
        return -1;

    out[pos++] = 0x00;                      /* RP-MTI: RP-DATA (MS -> Network) */
    out[pos++] = rp_mr;                     /* RP-Message Reference */
    out[pos++] = 0x00;                      /* RP-Originator Address: length 0 (MO) */
    if (sca_len) {
        memcpy(out + pos, mbim_pdu, sca_total);  /* RP-Destination Address = SCA (LV) */
        pos += sca_total;
    } else {
        out[pos++] = 0x00;                  /* RP-Destination Address: length 0 (default SMSC) */
    }
    out[pos++] = (uint8_t)tpdu_len;         /* RP-User-Data length */
    memcpy(out + pos, mbim_pdu + sca_total, tpdu_len);  /* SMS-SUBMIT TPDU */
    pos += tpdu_len;

    return (int)pos;
}

int ims_rp_data_to_mbim_pdu(const uint8_t *rp, size_t rp_len,
                            uint8_t *out, size_t out_cap,
                            uint8_t *out_rp_mr)
{
    size_t pos = 0;
    size_t oa_lv;
    size_t mbim = 0;
    const uint8_t *oa;
    uint8_t oa_len, da_len, ud_len;

    if (!rp || !out || rp_len < 3)
        return -1;
    if ((rp[pos++] & 0x07) != 0x01)     /* RP-MTI must be RP-DATA (n->ms) */
        return -1;
    if (out_rp_mr)
        *out_rp_mr = rp[pos];
    pos++;                               /* RP-MR */

    oa = &rp[pos];                       /* RP-Originator Address (SMSC) */
    oa_len = rp[pos];
    oa_lv = (size_t)1 + oa_len;
    if (pos + oa_lv >= rp_len)
        return -1;
    pos += oa_lv;

    da_len = rp[pos];                    /* RP-Destination Address (empty for MT) */
    if (pos + 1 + (size_t)da_len >= rp_len)
        return -1;
    pos += 1 + (size_t)da_len;

    if (rp[pos] == 0x41 && pos + 1 < rp_len)   /* optional RP-UD IEI */
        pos++;
    ud_len = rp[pos++];                  /* RP-User-Data length */
    if (ud_len == 0 || pos + (size_t)ud_len > rp_len)
        return -1;

    /* MBIM PDU = [SCA = RP-OA LV][TPDU = RP-UD]. */
    if (oa_lv + (size_t)ud_len > out_cap)
        return -1;
    memcpy(out, oa, oa_lv);
    mbim += oa_lv;
    memcpy(out + mbim, &rp[pos], ud_len);
    mbim += ud_len;
    return (int)mbim;
}
