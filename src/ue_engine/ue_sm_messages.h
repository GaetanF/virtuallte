#ifndef UE_ENGINE_SM_MESSAGES_H
#define UE_ENGINE_SM_MESSAGES_H

#include <stdbool.h>
#include <stdint.h>

#include "ue_types.h"

enum ue_sm_pdu_request_type {
    UE_SM_PDU_REQUEST_INITIAL = 0,
    UE_SM_PDU_REQUEST_EXISTING,
};

enum ue_sm_pdu_reject_cause {
    UE_SM_PDU_REJECT_NONE = 0,
    UE_SM_PDU_REJECT_INSUFFICIENT_RESOURCES = 26,
    UE_SM_PDU_REJECT_MISSING_DNN = 27,
    UE_SM_PDU_REJECT_UNKNOWN_PDU_SESSION_TYPE = 28,
    UE_SM_PDU_REJECT_SEMANTIC_ERROR = 95,
};

struct ue_sm_pdu_session_est_request {
    uint32_t attempt_id;
    uint32_t pdu_session_id;
    uint8_t pti;
    enum ue_sm_pdu_request_type request_type;
    char dnn[64];
    char pdu_type[16];
    uint8_t s_nssai_sst;
    bool has_existing_session;
};

struct ue_sm_pdu_session_est_result {
    bool submitted;
    enum ue_reject_class reject_class;
    enum ue_sm_pdu_reject_cause reject_cause;
    uint32_t selected_psi;
    uint8_t assigned_ipv4[4];
    uint32_t assigned_mtu;
};

struct ue_sm_pdu_session_rel_request {
    uint32_t attempt_id;
    uint32_t pdu_session_id;
    uint8_t pti;
};

struct ue_sm_pdu_session_rel_result {
    bool submitted;
    enum ue_reject_class reject_class;
    enum ue_sm_pdu_reject_cause reject_cause;
};

#endif
