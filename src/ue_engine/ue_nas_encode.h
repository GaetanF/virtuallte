#ifndef UE_NAS_ENCODE_H
#define UE_NAS_ENCODE_H

/*
 * ue_nas_encode - NAS uplink message encoder.
 *
 * Encodes the NAS PDUs the UE sends to the network:
 *   - Registration Request
 *   - Authentication Response
 *   - Security Mode Complete
 *   - Identity Response (SUCI)
 *   - UL NAS Transport (carrying PDU Session Establishment Request)
 *   - PDU Session Release Complete (inside UL NAS Transport)
 *
 * UERANSIM anchor:
 *   - src/lib/nas/encode.cpp
 *   - src/ue/nas/mm/register.cpp   : sendRegistrationRequest
 *   - src/ue/nas/mm/auth.cpp       : sendAuthResponse
 *   - src/ue/nas/mm/security.cpp   : sendSecurityModeComplete
 *   - src/ue/nas/mm/identity.cpp   : sendIdentityResponse
 *   - src/ue/nas/sm/establishment.cpp : sendEstablishmentRequest
 *
 * Wire format: TS 24.501 (5G NAS)
 *   MM messages: EPD(0x7E) + SHT(0x00) + MsgType + IEs
 *   SM messages: EPD(0x2E) + PSI + PTI + MsgType + IEs
 *   UL NAS Transport: EPD(0x7E) + SHT(0x00) + 0x67 + payload container
 *
 * NOTE: These encode plain (unprotected) NAS messages.
 * Security protection (integrity + optional ciphering) wraps
 * the plain message in a security header when a NAS security
 * context is established.
 */

#include <stddef.h>
#include <stdint.h>

/*
 * SUCI (Subscription Concealed Identifier) encoding for Identity Response.
 * In null-scheme (no home network public key), SUCI = SUPI = IMSI in BCD.
 *
 * Format (TS 24.501 §9.11.3.4):
 *   Type: 5GS mobile identity type = SUCI (0b0001)
 *   SUPI format: IMSI (0b000)
 *   MCC/MNC: BCD encoded
 *   Routing indicator: BCD (0000 = not configured)
 *   Protection scheme: null (0x00)
 *   Home network public key identifier: 0x00
 *   Scheme output: MSIN in BCD
 */

/*
 * Encode a 5GS Registration Request (initial registration).
 *
 * TS 24.501 §8.2.6:
 *   EPD(0x7E) + SHT(0x00) + MsgType(0x41)
 *   + 5GS registration type (half-octet) + ngKSI (half-octet)
 *   + 5GS mobile identity (SUCI, LV-E)
 *   + UE security capability (TLV)
 *
 * imsi: IMSI string (e.g. "001010000000001")
 * mcc/mnc: PLMN strings (e.g. "001", "01")
 * initial_cleartext: omit non-cleartext IEs for InitialUEMessage.
 *
 * Returns encoded length, or -1 on error.
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
                                       int initial_cleartext);

/*
 * Encode a Registration Complete (TS 24.501 §8.2.39).
 * Sent after a Registration Accept that carried a 5G-GUTI.
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_registration_complete(uint8_t *buf, size_t buf_len);

/*
 * 5GMM Deregistration Request (UE originating). When switch_off is non-zero it
 * is a "switch off" detach: fire-and-forget, no Deregistration Accept expected.
 * The 5GS mobile identity carried is the stored 5G-GUTI (guti/guti_len).
 */
int ue_nas_encode_deregistration_request(uint8_t *buf, size_t buf_len,
                                         int switch_off,
                                         const uint8_t *guti, size_t guti_len,
                                         uint8_t ngksi);

/*
 * Encode a Configuration Update Complete (TS 24.501 §8.2.20).
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_configuration_update_complete(uint8_t *buf, size_t buf_len);

/*
 * Encode an Authentication Response.
 *
 * TS 24.501 §8.2.2:
 *   EPD(0x7E) + SHT(0x00) + MsgType(0x57)
 *   + Authentication response parameter (RES*, TLV, IEI=0x2D)
 *
 * res: RES* value (16 bytes from Milenage computation)
 *
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_auth_response(uint8_t *buf, size_t buf_len,
                                const uint8_t *res, size_t res_len);

/*
 * Encode an Authentication Failure (TS 24.501 §8.2.4).
 * cause: 0x14 MAC failure, 0x15 synch failure.
 * auts/auts_len: AUTS resync token for synch failure (else NULL/0).
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_auth_failure(uint8_t *buf, size_t buf_len, uint8_t cause,
                               const uint8_t *auts, size_t auts_len);

/*
 * Encode a UL NAS Transport carrying a 5GSM STATUS (TS 24.501 §8.3.13).
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_sm_status(uint8_t *buf, size_t buf_len,
                            uint8_t psi, uint8_t pti, uint8_t cause);

/*
 * Encode a Security Mode Complete.
 *
 * TS 24.501 §8.2.26:
 *   EPD(0x7E) + SHT(0x00) + MsgType(0x5E)
 *   + Optional: IMEISV (IEI=0x77, TLV-E)
 *   + Optional: NAS message container (IEI=0x71, TLV-E)
 *
 * nas_container: if non-NULL, the Registration Request to include
 *                in the NAS message container (re-sent under security)
 *
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_security_mode_complete(uint8_t *buf, size_t buf_len,
                                         const uint8_t *nas_container,
                                         size_t nas_container_len);

/*
 * Encode an Identity Response (SUCI).
 *
 * TS 24.501 §8.2.22:
 *   EPD(0x7E) + SHT(0x00) + MsgType(0x5C)
 *   + 5GS mobile identity (SUCI, LV-E)
 *
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_identity_response(uint8_t *buf, size_t buf_len,
                                    const char *imsi,
                                    const char *mcc,
                                    const char *mnc);

/*
 * Encode a UL NAS Transport carrying a PDU Session Establishment Request.
 *
 * TS 24.501 §8.2.10 (UL NAS Transport):
 *   EPD(0x7E) + SHT(0x00) + MsgType(0x67)
 *   + Payload container type (4 bits, lower nibble = 0x01 N1 SM)
 *   + Spare half-octet (upper nibble)
 *   + Payload container length (2 bytes)
 *   + Payload container (SM NAS message)
 *   + Optional IEI 0x12: PDU Session ID (TV, 1+1)
 *   + Optional IEI 0x59: Request type (TV, 1+1)
 *   + Optional IEI 0x22: S-NSSAI (TLV)
 *   + Optional IEI 0x25: DNN (TLV)
 *
 * The inner SM message is PDU Session Establishment Request:
 *   EPD(0x2E) + PSI + PTI + MsgType(0xC1)
 *   + integrity protection max data rate (2 bytes)
 *   + optional IE1 PDU session type (IEI=0x9)
 *   + optional IE1 SSC mode (IEI=0xA)
 *
 * psi: PDU Session Identity (1-15)
 * pdu_session_type: 1=IPv4, 2=IPv6, 3=IPv4v6
 * dnn: DNN string (e.g. "internet")
 * s_nssai_sst: S-NSSAI SST (1 byte), 0 to omit
 *
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_pdu_session_est_request(uint8_t *buf, size_t buf_len,
                                          uint8_t psi,
                                          uint8_t pti,
                                          uint8_t pdu_session_type,
                                          uint8_t request_type,
                                          const char *dnn,
                                          uint8_t s_nssai_sst);

/*
 * Encode a UL NAS Transport carrying a PDU Session Release Complete.
 *
 * Returns encoded length, or -1 on error.
 */
int ue_nas_encode_pdu_session_release_complete(uint8_t *buf, size_t buf_len,
                                               uint8_t psi, uint8_t pti);

/*
 * Encode a UL NAS Transport carrying a PDU Session Release Request
 * (UE-initiated release). Returns encoded length, or -1 on error.
 */
int ue_nas_encode_pdu_session_release_request(uint8_t *buf, size_t buf_len,
                                              uint8_t psi, uint8_t pti);

/*
 * Helper: encode SUCI mobile identity into buffer.
 * Returns number of bytes written, or -1 on error.
 */
int ue_nas_encode_suci(uint8_t *buf, size_t buf_len,
                       const char *imsi,
                       const char *mcc,
                       const char *mnc);

#endif
