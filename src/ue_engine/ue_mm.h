#ifndef UE_ENGINE_MM_H
#define UE_ENGINE_MM_H

#include <stdbool.h>
#include <stdint.h>

#include "ue_types.h"
#include "ue_mm_messages.h"

struct ue_mm_ctx {
    enum ue_mm_state state;
    enum ue_mm_procedure procedure;
    enum ue_mm_proc_step proc_step;
    enum ue_mm_last_cause last_cause;
    enum ue_reject_class last_reject_class;
    uint32_t last_reject_cause_code;
    bool register_requested;
    uint8_t retry_count;
    uint8_t max_retries;
    uint32_t registration_attempt_id;
    char last_assigned_guti[32];
    char imsi[32];
    char mcc[8];
    char mnc[8];
    enum ue_mm_reg_type pending_reg_type;
    enum ue_mm_reg_trigger pending_reg_trigger;
    uint64_t next_step_deadline_ms;
};

void ue_mm_init(struct ue_mm_ctx *mm, bool radio_on, bool sim_present);
void ue_mm_on_radio(struct ue_mm_ctx *mm, bool on);
void ue_mm_on_sim(struct ue_mm_ctx *mm, bool sim_ready);
void ue_mm_set_profile(struct ue_mm_ctx *mm,
                       const char *imsi,
                       const char *mcc,
                       const char *mnc);
void ue_mm_request_register(struct ue_mm_ctx *mm);
void ue_mm_request_mobility_update(struct ue_mm_ctx *mm);
void ue_mm_request_periodic_update(struct ue_mm_ctx *mm);
void ue_mm_on_cell_found(struct ue_mm_ctx *mm);
void ue_mm_transition_to_registering(struct ue_mm_ctx *mm);
void ue_mm_on_registration_accept(struct ue_mm_ctx *mm);
void ue_mm_on_registration_reject(struct ue_mm_ctx *mm, enum ue_mm_reg_reject_cause reject_cause);
void ue_mm_tick(struct ue_mm_ctx *mm, uint64_t now_ms);

#endif
