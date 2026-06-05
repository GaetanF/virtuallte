#include "ue_mm.h"
#include "ue_mm_messages.h"
#include "ue_network_adapter.h"

#include <string.h>

#include "../common/log.h"

enum {
    UE_MM_TIMEOUT_MS = 1200,
    UE_MM_DEFAULT_MAX_RETRIES = 2,
};

static void mm_enter_deregistered(struct ue_mm_ctx *mm,
                                  enum ue_mm_last_cause cause,
                                  bool clear_request);
static void mm_retry_registration_attempt(struct ue_mm_ctx *mm, uint64_t next_deadline_ms);

static void mm_start_registration_procedure(struct ue_mm_ctx *mm);

/*
 * UERANSIM anchor:
 * - register.cpp: separate entry points for initial vs mobility/periodic registration.
 * - proc.cpp: procedure invocation based on pending cause/trigger.
 */
static void mm_invoke_pending_registration(struct ue_mm_ctx *mm)
{
    if (!mm || !mm->register_requested)
        return;

    if (mm->state != UE_MM_DEREGISTERED && mm->state != UE_MM_REGISTERED_HOME) {
        LOG_DBG(MM, "invoke_registration skipped: state=%d (need DEREGISTERED=%d or REGISTERED_HOME=%d)",
                mm->state, UE_MM_DEREGISTERED, UE_MM_REGISTERED_HOME);
        return;
    }

    mm_start_registration_procedure(mm);
}

static enum ue_reject_class mm_reject_class_from_cause(enum ue_mm_reg_reject_cause cause)
{
    switch (cause) {
    case UE_MM_REG_REJECT_CONGESTION:
        return UE_REJECT_TEMPORARY;
    case UE_MM_REG_REJECT_ILLEGAL_UE:
    case UE_MM_REG_REJECT_PLMN_NOT_ALLOWED:
    case UE_MM_REG_REJECT_TA_NOT_ALLOWED:
        return UE_REJECT_PERMANENT;
    case UE_MM_REG_REJECT_NONE:
    default:
        return UE_REJECT_TEMPORARY;
    }
}

static void mm_handle_reject_by_procedure(struct ue_mm_ctx *mm,
                                          enum ue_mm_reg_reject_cause reject_cause)
{
    enum ue_reject_class reject_class = mm_reject_class_from_cause(reject_cause);

    mm->last_reject_class = reject_class;
    mm->last_reject_cause_code = reject_cause;

    if (mm->procedure != UE_MM_PROC_REGISTRATION ||
        mm->proc_step != UE_MM_STEP_WAIT_REGISTRATION_RESPONSE) {
        mm_enter_deregistered(mm, UE_MM_CAUSE_REGISTRATION_REJECTED, true);
        return;
    }

    if (reject_class == UE_REJECT_TEMPORARY && mm->retry_count < mm->max_retries) {
        mm_retry_registration_attempt(mm, 0);
        return;
    }

    mm_enter_deregistered(mm, UE_MM_CAUSE_REGISTRATION_REJECTED, true);
}

static int mm_build_registration_request(struct ue_mm_ctx *mm,
                                         struct ue_mm_registration_request *req)
{
    if (!mm || !req)
        return -1;
    req->attempt_id = mm->registration_attempt_id;
    req->reg_type = mm->pending_reg_type;
    req->trigger = mm->pending_reg_trigger;
    req->with_sim = true;
    strncpy(req->suci, mm->imsi, sizeof(req->suci) - 1);
    req->suci[sizeof(req->suci) - 1] = '\0';
    strncpy(req->plmn_mcc, mm->mcc, sizeof(req->plmn_mcc) - 1);
    req->plmn_mcc[sizeof(req->plmn_mcc) - 1] = '\0';
    strncpy(req->plmn_mnc, mm->mnc, sizeof(req->plmn_mnc) - 1);
    req->plmn_mnc[sizeof(req->plmn_mnc) - 1] = '\0';
    return 0;
}

static struct ue_mm_registration_result mm_submit_registration_request(const struct ue_mm_registration_request *req)
{
    return ue_network_mm_submit_registration(req);
}

static void mm_handle_registration_submit_result(struct ue_mm_ctx *mm,
                                                 const struct ue_mm_registration_result *result)
{
    if (!mm)
        return;
    if (!result)
        return;

    if (result->submitted) {
        if (result->accept_result == UE_MM_REG_ACCEPT_NON_3GPP) {
            /*
             * Current fake_mbim scope choice: treat NON_3GPP registration accept
             * as terminal reject for the in-process UE flow. This is an explicit
             * perimeter simplification for now, not a general NAS rule.
             */
            mm->last_reject_class = UE_REJECT_PERMANENT;
            mm->last_reject_cause_code = UE_MM_REG_REJECT_PLMN_NOT_ALLOWED;
            mm_enter_deregistered(mm, UE_MM_CAUSE_REGISTRATION_REJECTED, true);
            return;
        }

        strncpy(mm->last_assigned_guti, result->assigned_guti, sizeof(mm->last_assigned_guti) - 1);
        mm->last_assigned_guti[sizeof(mm->last_assigned_guti) - 1] = '\0';
        mm->last_reject_class = UE_REJECT_TEMPORARY;
        mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
        return;
    }

    mm->last_reject_class = result->reject_class;
    mm->last_reject_cause_code = result->reject_cause;

    mm_handle_reject_by_procedure(mm, result->reject_cause);
}

static void mm_enter_deregistered(struct ue_mm_ctx *mm,
                                  enum ue_mm_last_cause cause,
                                  bool clear_request)
{
    mm->state = UE_MM_DEREGISTERED;
    mm->procedure = UE_MM_PROC_IDLE;
    mm->proc_step = UE_MM_STEP_NONE;
    mm->last_cause = cause;
    if (clear_request) {
        mm->register_requested = false;
        mm->retry_count = 0;
    }
    mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
    mm->next_step_deadline_ms = 0;
}

static void mm_start_registration_procedure(struct ue_mm_ctx *mm)
{
    mm->registration_attempt_id++;
    mm->state = UE_MM_SEARCHING;
    mm->procedure = UE_MM_PROC_REGISTRATION;
    mm->proc_step = UE_MM_STEP_WAIT_CELL_SELECTION;
    mm->last_cause = UE_MM_CAUSE_REGISTER_REQUESTED;
    mm->last_reject_class = UE_REJECT_TEMPORARY;
    mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
    mm->next_step_deadline_ms = 0;
    LOG_INF(MM, "registration procedure started attempt=%d state=SEARCHING", mm->registration_attempt_id);
}

static void mm_set_pending_initial_registration(struct ue_mm_ctx *mm)
{
    mm->pending_reg_type = UE_MM_REG_INITIAL;
    mm->pending_reg_trigger = UE_MM_REG_TRIGGER_EXPLICIT_REQUEST;
}

static void mm_set_pending_mobility_update(struct ue_mm_ctx *mm)
{
    mm->pending_reg_type = UE_MM_REG_MOBILITY_UPDATE;
    mm->pending_reg_trigger = UE_MM_REG_TRIGGER_MOBILITY_CHANGE;
}

static void mm_set_pending_periodic_update(struct ue_mm_ctx *mm)
{
    mm->pending_reg_type = UE_MM_REG_MOBILITY_UPDATE;
    mm->pending_reg_trigger = UE_MM_REG_TRIGGER_PERIODIC_UPDATE;
}

static void mm_retry_registration_attempt(struct ue_mm_ctx *mm, uint64_t next_deadline_ms)
{
    mm->retry_count++;
    mm->registration_attempt_id++;
    mm->state = UE_MM_SEARCHING;
    mm->procedure = UE_MM_PROC_REGISTRATION;
    mm->proc_step = UE_MM_STEP_WAIT_CELL_SELECTION;
    mm->last_cause = UE_MM_CAUSE_REGISTRATION_RETRY;
    mm->last_reject_class = UE_REJECT_TEMPORARY;
    mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
    mm->next_step_deadline_ms = next_deadline_ms;
}

static void mm_handle_wait_cell_selection(struct ue_mm_ctx *mm, uint64_t now_ms)
{
    if (mm->next_step_deadline_ms == 0)
        mm->next_step_deadline_ms = now_ms + UE_MM_TIMEOUT_MS;

    if (now_ms < mm->next_step_deadline_ms)
        return;

    if (mm->retry_count < mm->max_retries) {
        mm_retry_registration_attempt(mm, now_ms + UE_MM_TIMEOUT_MS);
        return;
    }

    mm_enter_deregistered(mm, UE_MM_CAUSE_REGISTRATION_TIMEOUT, true);
    mm->last_reject_class = UE_REJECT_TEMPORARY;
}

static void mm_handle_wait_registration_response(struct ue_mm_ctx *mm, uint64_t now_ms)
{
    if (mm->next_step_deadline_ms == 0)
        mm->next_step_deadline_ms = now_ms + UE_MM_TIMEOUT_MS;

    if (now_ms < mm->next_step_deadline_ms)
        return;

    if (mm->retry_count < mm->max_retries) {
        mm_retry_registration_attempt(mm, now_ms + UE_MM_TIMEOUT_MS);
        return;
    }

    mm_enter_deregistered(mm, UE_MM_CAUSE_REGISTRATION_TIMEOUT, true);
    mm->last_reject_class = UE_REJECT_TEMPORARY;
}

void ue_mm_init(struct ue_mm_ctx *mm, bool radio_on, bool sim_present)
{
    mm->procedure = UE_MM_PROC_IDLE;
    mm->proc_step = UE_MM_STEP_NONE;
    mm->last_cause = UE_MM_CAUSE_NONE;
    mm->last_reject_class = UE_REJECT_TEMPORARY;
    mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
    mm->register_requested = false;
    mm->pending_reg_type = UE_MM_REG_INITIAL;
    mm->pending_reg_trigger = UE_MM_REG_TRIGGER_EXPLICIT_REQUEST;
    mm->last_assigned_guti[0] = '\0';
    mm->retry_count = 0;
    mm->max_retries = UE_MM_DEFAULT_MAX_RETRIES;
    mm->next_step_deadline_ms = 0;

    if (!radio_on) {
        mm->state = UE_MM_POWERED_OFF;
        mm->last_cause = UE_MM_CAUSE_RADIO_OFF;
        mm->last_reject_class = UE_REJECT_TEMPORARY;
        mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
        mm->last_assigned_guti[0] = '\0';
        return;
    }
    mm->state = sim_present ? UE_MM_DEREGISTERED : UE_MM_SIM_NOT_READY;
    mm->last_cause = sim_present ? UE_MM_CAUSE_POWER_ON : UE_MM_CAUSE_SIM_NOT_READY;
    mm->last_reject_class = UE_REJECT_TEMPORARY;
    mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
}

void ue_mm_on_radio(struct ue_mm_ctx *mm, bool on)
{
    if (!on) {
        mm->state = UE_MM_POWERED_OFF;
        mm->procedure = UE_MM_PROC_IDLE;
        mm->proc_step = UE_MM_STEP_NONE;
        mm->last_cause = UE_MM_CAUSE_RADIO_OFF;
        mm->last_reject_class = UE_REJECT_TEMPORARY;
        mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
        mm->register_requested = false;
        mm->retry_count = 0;
        mm->next_step_deadline_ms = 0;
        return;
    }

    if (mm->state == UE_MM_SIM_NOT_READY)
        return;
    mm_enter_deregistered(mm, UE_MM_CAUSE_POWER_ON, true);
    mm->last_reject_class = UE_REJECT_TEMPORARY;
    mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
}

void ue_mm_on_sim(struct ue_mm_ctx *mm, bool sim_ready)
{
    if (!sim_ready) {
        mm->state = UE_MM_SIM_NOT_READY;
        mm->procedure = UE_MM_PROC_IDLE;
        mm->proc_step = UE_MM_STEP_NONE;
        mm->last_cause = UE_MM_CAUSE_SIM_NOT_READY;
        mm->last_reject_class = UE_REJECT_TEMPORARY;
        mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
        mm->register_requested = false;
        mm->retry_count = 0;
        mm->next_step_deadline_ms = 0;
        return;
    }

    if (mm->state == UE_MM_SIM_NOT_READY)
        mm->state = UE_MM_DEREGISTERED;
    if (sim_ready)
        mm->last_cause = UE_MM_CAUSE_SIM_BECAME_READY;
}

void ue_mm_set_profile(struct ue_mm_ctx *mm,
                       const char *imsi,
                       const char *mcc,
                       const char *mnc)
{
    if (!mm)
        return;

    if (imsi) {
        strncpy(mm->imsi, imsi, sizeof(mm->imsi) - 1);
        mm->imsi[sizeof(mm->imsi) - 1] = '\0';
    }
    if (mcc) {
        strncpy(mm->mcc, mcc, sizeof(mm->mcc) - 1);
        mm->mcc[sizeof(mm->mcc) - 1] = '\0';
    }
    if (mnc) {
        strncpy(mm->mnc, mnc, sizeof(mm->mnc) - 1);
        mm->mnc[sizeof(mm->mnc) - 1] = '\0';
    }
}

void ue_mm_request_register(struct ue_mm_ctx *mm)
{
    mm->register_requested = true;
    mm->retry_count = 0;
    mm_set_pending_initial_registration(mm);
    mm_invoke_pending_registration(mm);
}

void ue_mm_request_mobility_update(struct ue_mm_ctx *mm)
{
    mm->register_requested = true;
    mm->retry_count = 0;
    mm_set_pending_mobility_update(mm);
    mm_invoke_pending_registration(mm);
}

void ue_mm_request_periodic_update(struct ue_mm_ctx *mm)
{
    mm->register_requested = true;
    mm->retry_count = 0;
    mm_set_pending_periodic_update(mm);
    mm_invoke_pending_registration(mm);
}

void ue_mm_on_cell_found(struct ue_mm_ctx *mm)
{
    struct ue_mm_registration_request req;
    struct ue_mm_registration_result res;

    if (mm->state == UE_MM_SEARCHING &&
        mm->register_requested &&
        mm->proc_step == UE_MM_STEP_WAIT_CELL_SELECTION) {
        LOG_DBG(MM, "cell found, building registration request attempt=%d", mm->registration_attempt_id);
        if (mm_build_registration_request(mm, &req) < 0) {
            LOG_ERR(MM, "failed to build registration request");
            res.submitted = false;
            res.reject_class = UE_REJECT_TEMPORARY;
            res.reject_cause = UE_MM_REG_REJECT_CONGESTION;
            mm_handle_registration_submit_result(mm, &res);
            return;
        }
        res = mm_submit_registration_request(&req);
        LOG_DBG(MM, "registration request submitted=%s", res.submitted ? "yes" : "no");
        mm_handle_registration_submit_result(mm, &res);
        if (mm->state != UE_MM_SEARCHING)
            return;
        mm->state = UE_MM_REGISTERING;
        mm->proc_step = UE_MM_STEP_WAIT_REGISTRATION_RESPONSE;
        mm->next_step_deadline_ms = 0;
    }
}

/*
 * Transition MM to REGISTERING without submitting NAS.
 * Used in REAL backend: the engine handles RRC setup,
 * and NAS Registration Request is sent in RRCSetupComplete.
 */
void ue_mm_transition_to_registering(struct ue_mm_ctx *mm)
{
    if (!mm)
        return;
    mm->state = UE_MM_REGISTERING;
    mm->proc_step = UE_MM_STEP_WAIT_REGISTRATION_RESPONSE;
    mm->next_step_deadline_ms = 0;
    LOG_INF(MM, "transitioned to REGISTERING (attempt=%d)", mm->registration_attempt_id);
}

void ue_mm_on_registration_accept(struct ue_mm_ctx *mm)
{
    if (mm->state == UE_MM_REGISTERING && mm->register_requested) {
        mm->state = UE_MM_REGISTERED_HOME;
        mm->procedure = UE_MM_PROC_IDLE;
        mm->proc_step = UE_MM_STEP_NONE;
        mm->last_cause = UE_MM_CAUSE_REGISTRATION_ACCEPTED;
        mm->last_reject_class = UE_REJECT_TEMPORARY;
        mm->last_reject_cause_code = UE_MM_REG_REJECT_NONE;
        mm->register_requested = false;
        mm->retry_count = 0;
        mm->next_step_deadline_ms = 0;
    }
}

void ue_mm_on_registration_reject(struct ue_mm_ctx *mm, enum ue_mm_reg_reject_cause reject_cause)
{
    if (mm->state == UE_MM_REGISTERING && mm->register_requested) {
        mm_handle_reject_by_procedure(mm, reject_cause);
    }
}

void ue_mm_tick(struct ue_mm_ctx *mm, uint64_t now_ms)
{
    if (mm->state == UE_MM_SEARCHING &&
        mm->register_requested &&
        mm->proc_step == UE_MM_STEP_WAIT_CELL_SELECTION) {
        mm_handle_wait_cell_selection(mm, now_ms);
        return;
    }

    if (mm->state == UE_MM_REGISTERING &&
        mm->register_requested &&
        mm->proc_step == UE_MM_STEP_WAIT_REGISTRATION_RESPONSE) {
        mm_handle_wait_registration_response(mm, now_ms);
        return;
    }

    if (mm->state != UE_MM_REGISTERING && mm->state != UE_MM_SEARCHING) {
        mm->procedure = UE_MM_PROC_IDLE;
        mm->proc_step = UE_MM_STEP_NONE;
    }
    mm->next_step_deadline_ms = 0;
}
