#ifndef UE_CONTEXT_H
#define UE_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#include "ue_instance_config.h"

enum ue_reg_state {
    UE_REG_DEREG = 0,
    UE_REG_SEARCHING,
    UE_REG_HOME,
};

enum ue_packet_state {
    UE_PACKET_DETACHED = 0,
    UE_PACKET_ATTACHING,
    UE_PACKET_ATTACHED,
};

enum ue_session_state {
    UE_SESSION_DEACTIVATED = 0,
    UE_SESSION_ACTIVATING,
    UE_SESSION_ACTIVATED,
};

struct ue_runtime_ip {
    uint8_t ipv4_addr[4];
    uint8_t ipv4_gw[4];
    uint8_t dns1[4];
    uint8_t dns2[4];
    uint32_t mtu;
};

struct ue_nas_ctx {
    uint32_t last_tau_id;
};

struct ue_session_ctx {
    uint32_t session_id;
};

struct ue_timers_ctx {
    uint64_t reg_deadline_ms;
    uint64_t packet_deadline_ms;
    uint64_t session_deadline_ms;
};

struct ue_context {
    uint32_t ue_id;
    bool radio_on;
    bool sim_ready;
    enum ue_reg_state reg_state;
    enum ue_packet_state packet_state;
    enum ue_session_state session_state;
    bool running;

    struct ue_instance_config cfg;
    char active_dnn[64];
    struct ue_runtime_ip ip;

    struct ue_nas_ctx nas;
    struct ue_session_ctx session;
    struct ue_timers_ctx timers;
};

int ue_context_init(struct ue_context *ctx, uint32_t ue_id);
int ue_context_init_from_config(struct ue_context *ctx,
                                uint32_t ue_id,
                                const struct ue_instance_config *cfg);
void ue_context_reset(struct ue_context *ctx);

#endif
