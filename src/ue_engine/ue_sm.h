#ifndef UE_ENGINE_SM_H
#define UE_ENGINE_SM_H

#include <stdbool.h>
#include <stdint.h>

#include "ue_types.h"
#include "ue_sm_messages.h"

struct ue_sm_ctx {
    enum ue_sm_state state;
    enum ue_sm_procedure procedure;
    enum ue_sm_proc_step proc_step;
    enum ue_sm_last_cause last_cause;
    enum ue_reject_class last_reject_class;
    uint32_t last_reject_cause_code;
    uint32_t session_id;
    char active_dnn[64];
    struct ue_engine_runtime_ip ip;
    bool connect_requested;
    bool disconnect_requested;
    uint8_t retry_count;
    uint8_t max_retries;
    uint32_t establishment_attempt_id;
    uint8_t pti;
    uint8_t next_pti;        /* simple PTI allocator cursor (1..254) */
    char pdu_type[16];
    uint8_t s_nssai_sst;
    uint64_t next_step_deadline_ms;
    uint8_t est_retx_count;  /* T3580 establishment retransmission counter */
};

void ue_sm_init(struct ue_sm_ctx *sm, const char *default_dnn);
void ue_sm_set_profile(struct ue_sm_ctx *sm,
                       const char *default_dnn,
                       const char *pdu_type);
void ue_sm_on_radio(struct ue_sm_ctx *sm, bool on);
void ue_sm_request_connect(struct ue_sm_ctx *sm, const char *dnn);
void ue_sm_request_disconnect(struct ue_sm_ctx *sm);
void ue_sm_on_pdu_session_established(struct ue_sm_ctx *sm);
void ue_sm_on_pdu_session_reject(struct ue_sm_ctx *sm, enum ue_sm_pdu_reject_cause reject_cause);
void ue_sm_on_pdu_session_released(struct ue_sm_ctx *sm);
void ue_sm_tick(struct ue_sm_ctx *sm, uint64_t now_ms, bool mm_registered);

#endif
