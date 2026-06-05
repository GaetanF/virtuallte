#ifndef IMS_RPDATA_H
#define IMS_RPDATA_H

#include <stddef.h>
#include <stdint.h>

/*
 * TS 24.011 RP-layer codec for SMS over IP (TS 24.341). Pure byte transforms,
 * factored out of ims_service.c so they can be unit-tested in isolation.
 */

/*
 * Build an MO RP-DATA RPDU (MS -> Network) wrapping an MBIM SMS PDU
 * (`[SCA-len][SCA][TPDU]`, 27.005 PDU mode): the SCA becomes the RP-Destination
 * Address (empty => default SMSC) and the TPDU becomes the RP-User-Data.
 * Returns the RPDU length, or <0 on bad input / insufficient capacity.
 */
int ims_build_rp_data(const uint8_t *mbim_pdu, size_t mbim_len,
                      uint8_t rp_mr, uint8_t *out, size_t out_cap);

/*
 * Parse an MT RP-DATA RPDU (Network -> MS) into an MBIM SMS PDU
 * (`[SCA = RP-OA LV][TPDU = RP-UD]`). Optionally returns the RP-MR. Returns the
 * MBIM PDU length, or <0 on malformed input / non-RP-DATA MTI.
 */
int ims_rp_data_to_mbim_pdu(const uint8_t *rp, size_t rp_len,
                            uint8_t *out, size_t out_cap,
                            uint8_t *out_rp_mr);

#endif /* IMS_RPDATA_H */
