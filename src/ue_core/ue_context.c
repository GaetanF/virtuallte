#include "ue_context.h"

#include <string.h>

int ue_context_init(struct ue_context *ctx, uint32_t ue_id)
{
    struct ue_instance_config cfg;

    if (ue_instance_config_set_defaults(&cfg) < 0)
        return -1;
    if (ue_instance_config_finalize(&cfg, ue_id, false) < 0)
        return -1;

    return ue_context_init_from_config(ctx, ue_id, &cfg);
}

int ue_context_init_from_config(struct ue_context *ctx,
                                uint32_t ue_id,
                                const struct ue_instance_config *cfg)
{
    if (!ctx)
        return -1;
    if (!cfg)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ue_id = ue_id;
    ctx->radio_on = true;
    ctx->sim_ready = cfg->sim.sim_present;
    ctx->reg_state = UE_REG_HOME;
    ctx->packet_state = UE_PACKET_ATTACHED;
    ctx->session_state = UE_SESSION_DEACTIVATED;
    ctx->running = false;
    ctx->cfg = *cfg;
    strncpy(ctx->active_dnn, cfg->network.dnn, sizeof(ctx->active_dnn) - 1);

    ctx->ip.ipv4_addr[0] = 1;
    ctx->ip.ipv4_addr[1] = 2;
    ctx->ip.ipv4_addr[2] = 3;
    ctx->ip.ipv4_addr[3] = 4;
    ctx->ip.ipv4_gw[0] = 5;
    ctx->ip.ipv4_gw[1] = 6;
    ctx->ip.ipv4_gw[2] = 7;
    ctx->ip.ipv4_gw[3] = 8;
    ctx->ip.dns1[0] = 9;
    ctx->ip.dns1[1] = 10;
    ctx->ip.dns1[2] = 11;
    ctx->ip.dns1[3] = 12;
    ctx->ip.dns2[0] = 1;
    ctx->ip.dns2[1] = 1;
    ctx->ip.dns2[2] = 1;
    ctx->ip.dns2[3] = 1;
    ctx->ip.mtu = 1500;
    ctx->session.session_id = 0;

    return 0;
}

void ue_context_reset(struct ue_context *ctx)
{
    if (!ctx)
        return;
    ue_context_init_from_config(ctx, ctx->ue_id, &ctx->cfg);
}
