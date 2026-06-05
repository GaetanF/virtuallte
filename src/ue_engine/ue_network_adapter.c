/*
 * ue_network_adapter.c - Real RAN backend seam for MM/SM network operations.
 *
 * Submit functions encode the NAS uplink message, protect it (when a NAS
 * security context is active), wrap it in an RRC ULInformationTransfer and
 * send it via ue_ran_transport_send_nas_pdu(). The result is {submitted=true}
 * on success; the real accept/reject arrives asynchronously via downlink NAS
 * PDU in ue_engine_tick().
 */

#include "ue_network_adapter.h"
#include "ue_nas_encode.h"
#include "ue_nas_security.h"
#include "ue_nas_decode.h"
#include "ue_ran_transport.h"
#include "ue_rrc.h"

#include <string.h>

#include "../common/log.h"

static struct ue_ran_transport_ctx *g_transport = NULL;
static struct ue_nas_security_ctx *g_nas_sec = NULL;

void ue_network_adapter_set_transport(struct ue_ran_transport_ctx *transport)
{
    g_transport = transport;
}

void ue_network_adapter_set_security_ctx(struct ue_nas_security_ctx *nas_sec)
{
    g_nas_sec = nas_sec;
}

/*
 * Wrap a NAS PDU in RRC ULInformationTransfer and send via RAN transport.
 * Returns 0 on success, -1 on error.
 */
static int send_nas_in_rrc(const uint8_t *nas_pdu, int nas_len)
{
    uint8_t secured_buf[8192 + 64];
    const uint8_t *send_pdu = nas_pdu;
    int send_len = nas_len;
    uint8_t rrc_buf[8192 + 64];
    int rrc_len;

    if (!g_transport || nas_len <= 0) {
        LOG_ERR(NAS, "send_nas_in_rrc: no transport or empty PDU (transport=%p len=%d)",
                (void*)g_transport, nas_len);
        return -1;
    }

    if (g_nas_sec && g_nas_sec->active) {
        send_len = ue_nas_security_protect_with_sht(secured_buf, sizeof(secured_buf),
                                                    g_nas_sec,
                                                    nas_pdu, (size_t)nas_len,
                                                    NAS_SHT_INTEGRITY_PROTECTED_CIPHERED);
        if (send_len <= 0) {
            LOG_ERR(NAS, "send_nas_in_rrc: NAS protect failed len=%d", nas_len);
            return -1;
        }
        send_pdu = secured_buf;
    }

    rrc_len = ue_rrc_encode_ul_info_transfer(rrc_buf, sizeof(rrc_buf),
                                             send_pdu, (size_t)send_len);
    if (rrc_len <= 0) {
        LOG_ERR(NAS, "send_nas_in_rrc: RRC encode failed ret=%d", rrc_len);
        return -1;
    }

    LOG_TRC(NAS, "send_nas_in_rrc: sending %d bytes NAS in %d bytes RRC (protected=%s)",
            send_len, rrc_len, (g_nas_sec && g_nas_sec->active) ? "yes" : "no");
    return ue_ran_transport_send_nas_pdu(g_transport,
                                        rrc_buf, (size_t)rrc_len,
                                        UE_RRC_CHANNEL_UL_DCCH);
}

/*
 * Map pdu_type string ("ipv4", "ipv6", "ipv4v6") to NAS PDU session type byte.
 */
static uint8_t pdu_type_from_string(const char *pdu_type)
{
    if (!pdu_type || pdu_type[0] == '\0')
        return 1;  /* default IPv4 */
    if (pdu_type[0] == 'i' || pdu_type[0] == 'I') {
        if (pdu_type[3] == '4' && pdu_type[4] == 'v')
            return 3;  /* IPv4v6 */
        if (pdu_type[3] == '6')
            return 2;  /* IPv6 */
        return 1;      /* IPv4 */
    }
    return 1;
}

struct ue_mm_registration_result ue_network_mm_submit_registration(
    const struct ue_mm_registration_request *req)
{
    struct ue_mm_registration_result result;
    uint8_t nas_buf[256];
    int nas_len;

    memset(&result, 0, sizeof(result));

    LOG_DBG(NAS, "submit_registration REAL: suci=%s plmn=%s%s",
            req->suci, req->plmn_mcc, req->plmn_mnc);

    nas_len = ue_nas_encode_registration_request(nas_buf, sizeof(nas_buf),
                                                 req->suci,
                                                 req->plmn_mcc,
                                                 req->plmn_mnc,
                                                 0,
                                                  1 /* initial */,
                                                  NULL, 0,
                                                  7 /* ngKSI: no key */,
                                                  1 /* initial cleartext */);
    if (nas_len > 0) {
        LOG_DBG(NAS, "Registration Request encoded %d bytes, sending via RRC", nas_len);
        send_nas_in_rrc(nas_buf, nas_len);
    } else {
        LOG_ERR(NAS, "Registration Request encode failed ret=%d", nas_len);
    }

    result.submitted = true;
    return result;
}

struct ue_sm_pdu_session_est_result ue_network_sm_submit_establish(
    const struct ue_sm_pdu_session_est_request *req)
{
    struct ue_sm_pdu_session_est_result result;
    uint8_t nas_buf[512];
    int nas_len;
    uint8_t psi;
    uint8_t pti;
    uint8_t pdu_type;
    uint8_t request_type;

    memset(&result, 0, sizeof(result));

    psi = (req->pdu_session_id > 0 && req->pdu_session_id <= 15)
          ? (uint8_t)req->pdu_session_id : 1;
    pti = req->pti ? req->pti : 1;
    pdu_type = pdu_type_from_string(req->pdu_type);
    request_type = (req->request_type == UE_SM_PDU_REQUEST_EXISTING) ? 2 : 1;

    nas_len = ue_nas_encode_pdu_session_est_request(
        nas_buf, sizeof(nas_buf),
        psi, pti, pdu_type, request_type,
        req->dnn,
        req->s_nssai_sst);

    if (nas_len > 0)
        send_nas_in_rrc(nas_buf, nas_len);

    result.submitted = true;
    result.selected_psi = psi;
    return result;
}

struct ue_sm_pdu_session_rel_result ue_network_sm_submit_release(
    const struct ue_sm_pdu_session_rel_request *req)
{
    struct ue_sm_pdu_session_rel_result result;
    uint8_t nas_buf[64];
    int nas_len;
    uint8_t psi;

    memset(&result, 0, sizeof(result));

    psi = (req->pdu_session_id > 0 && req->pdu_session_id <= 15)
          ? (uint8_t)req->pdu_session_id : 1;

    nas_len = ue_nas_encode_pdu_session_release_request(
        nas_buf, sizeof(nas_buf), psi, req->pti ? req->pti : 1);

    if (nas_len > 0)
        send_nas_in_rrc(nas_buf, nas_len);

    result.submitted = true;
    return result;
}
