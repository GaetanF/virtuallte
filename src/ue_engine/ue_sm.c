#include "ue_sm.h"
#include "ue_sm_messages.h"
#include "ue_network_adapter.h"

#include <string.h>

/* T3580: PDU session establishment retransmission timer (TS 24.501). */
#define UE_SM_T3580_MS        16000u
#define UE_SM_T3580_MAX_RETX  4
/* Bound for waiting on a network RELEASE COMMAND after a RELEASE REQUEST. */
#define UE_SM_RELEASE_WAIT_MS 16000u

/*
 * Allocate a Procedure Transaction Identity (1..254; 0 and 255 are reserved).
 * Single-session modem: a monotonically advancing cursor is sufficient to
 * give each procedure a distinct PTI.
 */
static uint8_t sm_alloc_pti(struct ue_sm_ctx *sm)
{
    if (sm->next_pti < 1 || sm->next_pti > 254)
        sm->next_pti = 1;
    sm->pti = sm->next_pti;
    sm->next_pti = (uint8_t)((sm->next_pti % 254) + 1);
    return sm->pti;
}

static void sm_enter_inactive(struct ue_sm_ctx *sm,
                              enum ue_sm_last_cause cause,
                              bool clear_connect,
                              bool clear_disconnect);
static void sm_retry_establish_procedure(struct ue_sm_ctx *sm);
static void sm_start_release_procedure(struct ue_sm_ctx *sm);

static enum ue_reject_class sm_reject_class_from_cause(enum ue_sm_pdu_reject_cause cause)
{
    switch (cause) {
    case UE_SM_PDU_REJECT_INSUFFICIENT_RESOURCES:
        return UE_REJECT_TEMPORARY;
    case UE_SM_PDU_REJECT_MISSING_DNN:
    case UE_SM_PDU_REJECT_UNKNOWN_PDU_SESSION_TYPE:
    case UE_SM_PDU_REJECT_SEMANTIC_ERROR:
        return UE_REJECT_PERMANENT;
    case UE_SM_PDU_REJECT_NONE:
    default:
        return UE_REJECT_TEMPORARY;
    }
}

static void sm_handle_establish_reject_by_procedure(struct ue_sm_ctx *sm,
                                                    enum ue_sm_pdu_reject_cause reject_cause)
{
    sm->last_reject_class = sm_reject_class_from_cause(reject_cause);
    sm->last_reject_cause_code = reject_cause;

    /* Free PTI on reject (UERANSIM: freeProcedureTransactionId) */
    sm->pti = 0;

    if (sm->procedure != UE_SM_PROC_ESTABLISH_PDU ||
        sm->proc_step != UE_SM_STEP_WAIT_ESTABLISH_RESPONSE) {
        sm_enter_inactive(sm, UE_SM_CAUSE_ESTABLISH_REJECTED, true, true);
        sm->retry_count = 0;
        return;
    }

    sm_enter_inactive(sm, UE_SM_CAUSE_ESTABLISH_REJECTED, false, true);

    /*
     * UERANSIM anchor (establishment.cpp): reject handling depends on
     * procedure/session context. For this scope, EXISTING request semantic
     * failures are terminal while resource pressure remains retryable.
     */
    if (reject_cause == UE_SM_PDU_REJECT_SEMANTIC_ERROR) {
        sm->connect_requested = false;
        sm->retry_count = 0;
        return;
    }

    if (sm->last_reject_class == UE_REJECT_TEMPORARY && sm->retry_count < sm->max_retries) {
        sm_retry_establish_procedure(sm);
    } else {
        sm->connect_requested = false;
        sm->retry_count = 0;
    }
}

static int sm_build_release_request(const struct ue_sm_ctx *sm,
                                    struct ue_sm_pdu_session_rel_request *req)
{
    if (!sm || !req)
        return -1;
    req->attempt_id = sm->establishment_attempt_id;
    req->pdu_session_id = sm->session_id;
    req->pti = sm->pti;
    return 0;
}

static struct ue_sm_pdu_session_rel_result sm_submit_release_request(const struct ue_sm_pdu_session_rel_request *req)
{
    return ue_network_sm_submit_release(req);
}

static void sm_handle_release_submit_result(struct ue_sm_ctx *sm,
                                            const struct ue_sm_pdu_session_rel_result *result)
{
    if (!sm || !result)
        return;

    if (result->submitted) {
        sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
        return;
    }

    sm->last_reject_class = sm_reject_class_from_cause(result->reject_cause);
    sm->last_reject_cause_code = result->reject_cause;
    sm_enter_inactive(sm, UE_SM_CAUSE_RELEASE_COMPLETE, true, true);
    sm->retry_count = 0;
}

static int sm_build_establish_request(const struct ue_sm_ctx *sm,
                                      struct ue_sm_pdu_session_est_request *req)
{
    if (!sm || !req)
        return -1;
    req->attempt_id = sm->establishment_attempt_id;
    req->pdu_session_id = sm->session_id ? sm->session_id : 1;
    req->pti = sm->pti ? sm->pti : 1;
    /*
     * Establishment always uses INITIAL_REQUEST (UERANSIM sendEstablishmentRequest).
     * EXISTING_PDU_SESSION is for handover/existing-session transport, which is
     * not implemented here; never advertise it for a fresh establishment.
     */
    req->request_type = UE_SM_PDU_REQUEST_INITIAL;
    strncpy(req->dnn, sm->active_dnn, sizeof(req->dnn) - 1);
    req->dnn[sizeof(req->dnn) - 1] = '\0';
    strncpy(req->pdu_type, sm->pdu_type, sizeof(req->pdu_type) - 1);
    req->pdu_type[sizeof(req->pdu_type) - 1] = '\0';
    req->s_nssai_sst = sm->s_nssai_sst;
    req->has_existing_session = sm->session_id != 0;
    return 0;
}

static struct ue_sm_pdu_session_est_result sm_submit_establish_request(const struct ue_sm_pdu_session_est_request *req)
{
    return ue_network_sm_submit_establish(req);
}

static void sm_handle_establish_submit_result(struct ue_sm_ctx *sm,
                                              const struct ue_sm_pdu_session_est_result *result)
{
    if (!sm)
        return;
    if (!result)
        return;
    if (result->submitted) {
        sm->session_id = result->selected_psi;
        sm->ip.ipv4_addr[0] = result->assigned_ipv4[0];
        sm->ip.ipv4_addr[1] = result->assigned_ipv4[1];
        sm->ip.ipv4_addr[2] = result->assigned_ipv4[2];
        sm->ip.ipv4_addr[3] = result->assigned_ipv4[3];
        sm->ip.mtu = result->assigned_mtu ? result->assigned_mtu : sm->ip.mtu;
        sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
        /* Free PTI on accept (UERANSIM: freeProcedureTransactionId) */
        sm->pti = 0;
        return;
    }

    sm_handle_establish_reject_by_procedure(sm, result->reject_cause);
}

void ue_sm_set_profile(struct ue_sm_ctx *sm,
                       const char *default_dnn,
                       const char *pdu_type)
{
    if (!sm)
        return;

    if (default_dnn && default_dnn[0] != '\0') {
        strncpy(sm->active_dnn, default_dnn, sizeof(sm->active_dnn) - 1);
        sm->active_dnn[sizeof(sm->active_dnn) - 1] = '\0';
    }
    if (pdu_type && pdu_type[0] != '\0') {
        strncpy(sm->pdu_type, pdu_type, sizeof(sm->pdu_type) - 1);
        sm->pdu_type[sizeof(sm->pdu_type) - 1] = '\0';
    }
}

static void sm_enter_inactive(struct ue_sm_ctx *sm,
                              enum ue_sm_last_cause cause,
                              bool clear_connect,
                              bool clear_disconnect)
{
    sm->state = UE_SM_INACTIVE;
    sm->procedure = UE_SM_PROC_IDLE;
    sm->proc_step = UE_SM_STEP_NONE;
    sm->last_cause = cause;
    if (clear_connect)
        sm->connect_requested = false;
    if (clear_disconnect)
        sm->disconnect_requested = false;
    sm->next_step_deadline_ms = 0;
    /* Free PTI on session teardown (UERANSIM: freeProcedureTransactionId) */
    sm->pti = 0;
}

static void sm_start_establish_procedure(struct ue_sm_ctx *sm)
{
    struct ue_sm_pdu_session_est_request req;
    struct ue_sm_pdu_session_est_result res;

    /* Allocate PTI (UERANSIM: allocateProcedureTransactionId) */
    sm_alloc_pti(sm);

    sm->establishment_attempt_id++;
    sm->state = UE_SM_ESTABLISHING;
    sm->procedure = UE_SM_PROC_ESTABLISH_PDU;
    sm->proc_step = UE_SM_STEP_WAIT_ESTABLISH_RESPONSE;
    sm->next_step_deadline_ms = 0;   /* armed by ue_sm_tick (T3580) */
    sm->est_retx_count = 0;

    if (sm_build_establish_request(sm, &req) < 0) {
        res.submitted = false;
        res.reject_class = UE_REJECT_TEMPORARY;
        res.reject_cause = UE_SM_PDU_REJECT_INSUFFICIENT_RESOURCES;
        sm_handle_establish_submit_result(sm, &res);
        return;
    }

    res = sm_submit_establish_request(&req);
    sm_handle_establish_submit_result(sm, &res);
}

static void sm_retry_establish_procedure(struct ue_sm_ctx *sm)
{
    sm->retry_count++;
    sm->connect_requested = true;
    sm->disconnect_requested = false;
    sm_start_establish_procedure(sm);
}

static void sm_start_release_procedure(struct ue_sm_ctx *sm)
{
    struct ue_sm_pdu_session_rel_request req;
    struct ue_sm_pdu_session_rel_result res;

    /* Allocate a fresh PTI for the UE-initiated release procedure. */
    sm_alloc_pti(sm);

    sm->state = UE_SM_RELEASING;
    sm->procedure = UE_SM_PROC_RELEASE_PDU;
    sm->proc_step = UE_SM_STEP_WAIT_RELEASE_COMPLETE;
    sm->next_step_deadline_ms = 0;   /* armed by ue_sm_tick (release wait) */

    if (sm_build_release_request(sm, &req) < 0) {
        res.submitted = false;
        res.reject_class = UE_REJECT_PERMANENT;
        res.reject_cause = UE_SM_PDU_REJECT_SEMANTIC_ERROR;
        sm_handle_release_submit_result(sm, &res);
        return;
    }

    res = sm_submit_release_request(&req);
    sm_handle_release_submit_result(sm, &res);
}

void ue_sm_init(struct ue_sm_ctx *sm, const char *default_dnn)
{
    memset(sm, 0, sizeof(*sm));
    sm->state = UE_SM_INACTIVE;
    sm->procedure = UE_SM_PROC_IDLE;
    sm->proc_step = UE_SM_STEP_NONE;
    sm->last_cause = UE_SM_CAUSE_NONE;
    sm->last_reject_class = UE_REJECT_TEMPORARY;
    sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
    sm->retry_count = 0;
    sm->max_retries = 1;
    sm->session_id = 0;
    sm->pti = 0;
    sm->s_nssai_sst = 1;  /* Default eMBB */
    if (default_dnn) {
        strncpy(sm->active_dnn, default_dnn, sizeof(sm->active_dnn) - 1);
        sm->active_dnn[sizeof(sm->active_dnn) - 1] = '\0';
    }
    strncpy(sm->pdu_type, "ipv4", sizeof(sm->pdu_type) - 1);

    sm->ip.ipv4_addr[0] = 1;
    sm->ip.ipv4_addr[1] = 2;
    sm->ip.ipv4_addr[2] = 3;
    sm->ip.ipv4_addr[3] = 4;
    sm->ip.ipv4_gw[0] = 5;
    sm->ip.ipv4_gw[1] = 6;
    sm->ip.ipv4_gw[2] = 7;
    sm->ip.ipv4_gw[3] = 8;
    sm->ip.dns1[0] = 9;
    sm->ip.dns1[1] = 10;
    sm->ip.dns1[2] = 11;
    sm->ip.dns1[3] = 12;
    sm->ip.dns2[0] = 1;
    sm->ip.dns2[1] = 1;
    sm->ip.dns2[2] = 1;
    sm->ip.dns2[3] = 1;
    sm->ip.mtu = 1500;
}

void ue_sm_on_radio(struct ue_sm_ctx *sm, bool on)
{
    if (!on) {
        sm_enter_inactive(sm, UE_SM_CAUSE_RADIO_OFF, true, true);
        sm->last_reject_class = UE_REJECT_TEMPORARY;
        sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
        sm->retry_count = 0;
    }
}

void ue_sm_request_connect(struct ue_sm_ctx *sm, const char *dnn)
{
    if (dnn && dnn[0] != '\0') {
        strncpy(sm->active_dnn, dnn, sizeof(sm->active_dnn) - 1);
        sm->active_dnn[sizeof(sm->active_dnn) - 1] = '\0';
    }

    sm->connect_requested = true;
    sm->disconnect_requested = false;
    sm->last_cause = UE_SM_CAUSE_CONNECT_REQUESTED;
    sm->last_reject_class = UE_REJECT_TEMPORARY;
    sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
    sm->retry_count = 0;
}

void ue_sm_request_disconnect(struct ue_sm_ctx *sm)
{
    sm->disconnect_requested = true;
    sm->connect_requested = false;
    sm->last_cause = UE_SM_CAUSE_DISCONNECT_REQUESTED;
    sm->last_reject_class = UE_REJECT_TEMPORARY;
    sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
}

void ue_sm_tick(struct ue_sm_ctx *sm, uint64_t now_ms, bool mm_registered)
{
    if (!mm_registered) {
        sm_enter_inactive(sm, UE_SM_CAUSE_MM_NOT_REGISTERED, true, true);
        sm->last_reject_class = UE_REJECT_TEMPORARY;
        sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
        sm->retry_count = 0;
        return;
    }

    if (sm->disconnect_requested) {
        if (sm->state == UE_SM_ACTIVE) {
            sm_start_release_procedure(sm);
        } else {
            sm_enter_inactive(sm, UE_SM_CAUSE_DISCONNECT_REQUESTED, false, true);
        }
    }

    if (sm->connect_requested && sm->state == UE_SM_INACTIVE) {
        sm->connect_requested = false;
        sm_start_establish_procedure(sm);
    }

    /*
     * T3580: retransmit the PDU Session Establishment Request on timeout,
     * reusing the same PSI/PTI (UERANSIM newTransactionTimer(3580)). After
     * UE_SM_T3580_MAX_RETX attempts with no Accept/Reject, abandon.
     */
    if (sm->state == UE_SM_ESTABLISHING &&
        sm->proc_step == UE_SM_STEP_WAIT_ESTABLISH_RESPONSE) {
        if (sm->next_step_deadline_ms == 0) {
            sm->next_step_deadline_ms = now_ms + UE_SM_T3580_MS;
        } else if (now_ms >= sm->next_step_deadline_ms) {
            if (sm->est_retx_count < UE_SM_T3580_MAX_RETX) {
                struct ue_sm_pdu_session_est_request req;
                sm->est_retx_count++;
                sm->next_step_deadline_ms = now_ms + UE_SM_T3580_MS;
                if (sm_build_establish_request(sm, &req) == 0)
                    (void)sm_submit_establish_request(&req);
            } else {
                sm_enter_inactive(sm, UE_SM_CAUSE_ESTABLISH_REJECTED, true, true);
                sm->est_retx_count = 0;
            }
        }
    }

    /* Bound the wait for a network RELEASE COMMAND after our RELEASE REQUEST. */
    if (sm->state == UE_SM_RELEASING &&
        sm->proc_step == UE_SM_STEP_WAIT_RELEASE_COMPLETE) {
        if (sm->next_step_deadline_ms == 0)
            sm->next_step_deadline_ms = now_ms + UE_SM_RELEASE_WAIT_MS;
        else if (now_ms >= sm->next_step_deadline_ms)
            sm_enter_inactive(sm, UE_SM_CAUSE_RELEASE_COMPLETE, true, true);
    }
}

void ue_sm_on_pdu_session_established(struct ue_sm_ctx *sm)
{
    if (sm->state == UE_SM_ESTABLISHING) {
        sm->state = UE_SM_ACTIVE;
        sm->procedure = UE_SM_PROC_IDLE;
        sm->proc_step = UE_SM_STEP_NONE;
        sm->last_cause = UE_SM_CAUSE_ESTABLISH_ACCEPTED;
        sm->last_reject_class = UE_REJECT_TEMPORARY;
        sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
        sm->session_id = 0;
        sm->connect_requested = false;
        sm->retry_count = 0;
        sm->next_step_deadline_ms = 0;
    }
}

void ue_sm_on_pdu_session_reject(struct ue_sm_ctx *sm, enum ue_sm_pdu_reject_cause reject_cause)
{
    if (sm->state == UE_SM_ESTABLISHING &&
        sm->proc_step == UE_SM_STEP_WAIT_ESTABLISH_RESPONSE) {
        sm_handle_establish_reject_by_procedure(sm, reject_cause);
    }
}

void ue_sm_on_pdu_session_released(struct ue_sm_ctx *sm)
{
    /*
     * Triggered when the network's RELEASE COMMAND has been acknowledged.
     * Handles both the UE-initiated case (state RELEASING, after our RELEASE
     * REQUEST) and the network-initiated case (session was ACTIVE).
     */
    if (sm->state == UE_SM_RELEASING || sm->state == UE_SM_ACTIVE) {
        sm_enter_inactive(sm, UE_SM_CAUSE_RELEASE_COMPLETE, true, true);
        sm->last_reject_class = UE_REJECT_TEMPORARY;
        sm->last_reject_cause_code = UE_SM_PDU_REJECT_NONE;
        sm->retry_count = 0;
    }
}
