#ifndef UE_ENGINE_MM_MESSAGES_H
#define UE_ENGINE_MM_MESSAGES_H

#include <stdbool.h>
#include <stdint.h>

#include "ue_types.h"

enum ue_mm_reg_type {
    UE_MM_REG_INITIAL = 0,
    UE_MM_REG_MOBILITY_UPDATE,
};

enum ue_mm_reg_trigger {
    UE_MM_REG_TRIGGER_EXPLICIT_REQUEST = 0,
    UE_MM_REG_TRIGGER_MOBILITY_CHANGE,
    UE_MM_REG_TRIGGER_PERIODIC_UPDATE,
};

enum ue_mm_reg_reject_cause {
    UE_MM_REG_REJECT_NONE = 0,
    UE_MM_REG_REJECT_ILLEGAL_UE = 3,
    UE_MM_REG_REJECT_CONGESTION = 22,
    UE_MM_REG_REJECT_PLMN_NOT_ALLOWED = 11,
    UE_MM_REG_REJECT_TA_NOT_ALLOWED = 12,
};

enum ue_mm_reg_accept_result {
    UE_MM_REG_ACCEPT_3GPP = 0,
    UE_MM_REG_ACCEPT_NON_3GPP,
};

struct ue_mm_registration_request {
    uint32_t attempt_id;
    enum ue_mm_reg_type reg_type;
    enum ue_mm_reg_trigger trigger;
    bool with_sim;
    char suci[32];
    char plmn_mcc[8];
    char plmn_mnc[8];
};

struct ue_mm_registration_result {
    bool submitted;
    enum ue_reject_class reject_class;
    enum ue_mm_reg_reject_cause reject_cause;
    enum ue_mm_reg_accept_result accept_result;
    char assigned_guti[32];
    uint32_t t3512_seconds;
};

#endif
