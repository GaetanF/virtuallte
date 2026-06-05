#ifndef UE_ENGINE_TYPES_H
#define UE_ENGINE_TYPES_H

#include <stdbool.h>
#include <stdint.h>

enum ue_mm_state {
    UE_MM_POWERED_OFF = 0,
    UE_MM_SIM_NOT_READY,
    UE_MM_DEREGISTERED,
    UE_MM_SEARCHING,
    UE_MM_REGISTERING,
    UE_MM_REGISTERED_HOME,
};

enum ue_sm_state {
    UE_SM_INACTIVE = 0,
    UE_SM_ESTABLISHING,
    UE_SM_ACTIVE,
    UE_SM_RELEASING,
};

enum ue_mm_procedure {
    UE_MM_PROC_IDLE = 0,
    UE_MM_PROC_REGISTRATION,
};

enum ue_mm_proc_step {
    UE_MM_STEP_NONE = 0,
    UE_MM_STEP_WAIT_CELL_SELECTION,
    UE_MM_STEP_WAIT_REGISTRATION_RESPONSE,
};

enum ue_mm_last_cause {
    UE_MM_CAUSE_NONE = 0,
    UE_MM_CAUSE_POWER_ON,
    UE_MM_CAUSE_SIM_BECAME_READY,
    UE_MM_CAUSE_REGISTER_REQUESTED,
    UE_MM_CAUSE_REGISTRATION_ACCEPTED,
    UE_MM_CAUSE_REGISTRATION_REJECTED,
    UE_MM_CAUSE_REGISTRATION_TIMEOUT,
    UE_MM_CAUSE_REGISTRATION_RETRY,
    UE_MM_CAUSE_RADIO_OFF,
    UE_MM_CAUSE_SIM_NOT_READY,
};

enum ue_sm_procedure {
    UE_SM_PROC_IDLE = 0,
    UE_SM_PROC_ESTABLISH_PDU,
    UE_SM_PROC_RELEASE_PDU,
};

enum ue_sm_proc_step {
    UE_SM_STEP_NONE = 0,
    UE_SM_STEP_WAIT_ESTABLISH_RESPONSE,
    UE_SM_STEP_WAIT_RELEASE_COMPLETE,
};

enum ue_sm_last_cause {
    UE_SM_CAUSE_NONE = 0,
    UE_SM_CAUSE_CONNECT_REQUESTED,
    UE_SM_CAUSE_ESTABLISH_ACCEPTED,
    UE_SM_CAUSE_ESTABLISH_REJECTED,
    UE_SM_CAUSE_DISCONNECT_REQUESTED,
    UE_SM_CAUSE_RELEASE_COMPLETE,
    UE_SM_CAUSE_MM_NOT_REGISTERED,
    UE_SM_CAUSE_RADIO_OFF,
};

enum ue_reject_class {
    UE_REJECT_TEMPORARY = 0,
    UE_REJECT_PERMANENT,
};

enum ue_engine_changed {
    UE_ENGINE_CHANGED_NONE = 0,
    UE_ENGINE_CHANGED_MM = 1u << 0,
    UE_ENGINE_CHANGED_SM = 1u << 1,
    UE_ENGINE_CHANGED_IP = 1u << 2,
    UE_ENGINE_CHANGED_IDENT = 1u << 3,
    UE_ENGINE_CHANGED_OPERATOR = 1u << 4,
    UE_ENGINE_CHANGED_DNN = 1u << 5,
};

struct ue_engine_runtime_ip {
    uint8_t ipv4_addr[4];
    uint8_t ipv4_gw[4];
    uint8_t dns1[4];
    uint8_t dns2[4];
    uint32_t mtu;
};

struct ue_engine_snapshot {
    bool running;
    bool radio_on;
    bool sim_ready;

    enum ue_mm_state mm_state;
    enum ue_sm_state sm_state;
    enum ue_mm_procedure mm_procedure;
    enum ue_sm_procedure sm_procedure;
    enum ue_mm_proc_step mm_proc_step;
    enum ue_sm_proc_step sm_proc_step;
    enum ue_mm_last_cause mm_last_cause;
    enum ue_sm_last_cause sm_last_cause;
    enum ue_reject_class mm_last_reject_class;
    enum ue_reject_class sm_last_reject_class;
    uint32_t mm_last_reject_cause_code;
    uint32_t sm_last_reject_cause_code;
    uint32_t mm_registration_attempt_id;
    uint32_t sm_establishment_attempt_id;
    uint32_t mm_pending_reg_type;
    uint32_t mm_pending_reg_trigger;
    char mm_last_assigned_guti[32];

    uint32_t session_id;
    char active_dnn[64];

    char imei[32];
    char imsi[32];
    char iccid[40];
    char manufacturer[64];
    char model[64];
    char firmware[64];
    char serial[64];

    char plmn[16];
    char operator_name[64];

    struct ue_engine_runtime_ip ip;
};

#endif
