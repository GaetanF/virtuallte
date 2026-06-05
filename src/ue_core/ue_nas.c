#include "ue_nas.h"

#include <string.h>

#include "ue_identity.h"
#include "ue_session.h"

int ue_core_init(struct ue_context *ctx,
                 uint32_t ue_id,
                 const struct ue_instance_config *cfg)
{
    if (ue_context_init_from_config(ctx, ue_id, cfg) < 0)
        return -1;

    ue_session_set_default_ip(ctx);
    ctx->session_state = UE_SESSION_DEACTIVATED;
    return 0;
}

int ue_core_start(struct ue_context *ctx)
{
    ctx->running = true;
    return 0;
}

int ue_core_stop(struct ue_context *ctx)
{
    ctx->running = false;
    return 0;
}

int ue_core_set_radio(struct ue_context *ctx, bool on)
{
    ctx->radio_on = on;

    if (!on) {
        ctx->reg_state = UE_REG_DEREG;
        ctx->packet_state = UE_PACKET_DETACHED;
        ctx->session_state = UE_SESSION_DEACTIVATED;
        ctx->timers.reg_deadline_ms = 0;
        ctx->timers.packet_deadline_ms = 0;
        ctx->timers.session_deadline_ms = 0;
    }

    return 0;
}

int ue_core_request_register(struct ue_context *ctx)
{
    if (!ctx->radio_on)
        return 0;

    ctx->reg_state = UE_REG_SEARCHING;
    ctx->packet_state = UE_PACKET_DETACHED;
    ctx->session_state = UE_SESSION_DEACTIVATED;
    ctx->timers.reg_deadline_ms = 0;
    ctx->timers.packet_deadline_ms = 0;
    ctx->timers.session_deadline_ms = 0;
    return 0;
}

int ue_core_request_connect(struct ue_context *ctx, const char *dnn)
{
    if (dnn && dnn[0] != '\0') {
        strncpy(ctx->active_dnn, dnn, sizeof(ctx->active_dnn) - 1);
        ctx->active_dnn[sizeof(ctx->active_dnn) - 1] = '\0';
    }

    if (ctx->packet_state == UE_PACKET_ATTACHED)
        ctx->session_state = UE_SESSION_ACTIVATING;
    return 0;
}

int ue_core_request_disconnect(struct ue_context *ctx)
{
    ctx->session_state = UE_SESSION_DEACTIVATED;
    return 0;
}

int ue_core_tick(struct ue_context *ctx, uint64_t now_ms)
{
    (void)now_ms;

    if (!ctx->running)
        return 0;

    if (ctx->reg_state == UE_REG_SEARCHING) {
        ctx->reg_state = UE_REG_HOME;
        ctx->packet_state = UE_PACKET_ATTACHING;
    } else if (ctx->packet_state == UE_PACKET_ATTACHING) {
        ctx->packet_state = UE_PACKET_ATTACHED;
        if (ctx->session_state == UE_SESSION_DEACTIVATED)
            ctx->session_state = UE_SESSION_ACTIVATING;
    } else if (ctx->session_state == UE_SESSION_ACTIVATING) {
        ctx->session_state = UE_SESSION_ACTIVATED;
        ctx->session.session_id = 0;
    }

    return 0;
}
