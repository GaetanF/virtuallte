#include "ue_context.h"
#include "ue_network_adapter.h"

#include <stdio.h>
#include <string.h>

#include "../common/log.h"

/*
 * Drain downlink DATA PDUs on the RLS receive thread. Registered as the
 * transport on_data_rx callback so downlink delivery is not gated by the
 * engine main-thread tick.
 */
static void ue_context_drain_downlink(void *up)
{
    ue_up_process_downlink((struct ue_up_ctx *)up);
}

int ue_context_init_from_config(struct ue_context *ctx,
                                uint32_t ue_id,
                                const struct ue_instance_config *cfg)
{
    if (!ctx || !cfg)
        return -1;

    memset(ctx, 0, sizeof(*ctx));
    ctx->ue_id = ue_id;
    ctx->cfg = *cfg;
    ctx->radio_on = true;
    ctx->sim_ready = cfg->sim.sim_present;

    ue_mm_init(&ctx->mm, ctx->radio_on, ctx->sim_ready);
    ue_sm_init(&ctx->sm, cfg->network.dnn);
    ue_mm_set_profile(&ctx->mm, cfg->sim.imsi, cfg->network.mcc, cfg->network.mnc);
    ue_sm_set_profile(&ctx->sm, cfg->network.dnn, cfg->network.pdu_type);

    /* Initialize user plane and RAN transport (target modules) */
    ue_up_init(&ctx->up);
    ue_ran_transport_init(&ctx->ran);

    /* Cross-link: user plane needs transport for data forwarding */
    ue_up_set_transport(&ctx->up, &ctx->ran);

    /* Downlink DATA is drained on the RLS receive thread, not the engine tick. */
    ue_ran_transport_set_data_rx_cb(&ctx->ran, ue_context_drain_downlink, &ctx->up);

    ctx->nas_sec.active = false;
    ctx->nas_sec.int_alg = UE_NIA0;
    ctx->nas_sec.enc_alg = UE_NEA0;
    ctx->nas_sec.bearer = 1;
    ctx->nas_sec.ngksi = 7;

    /* Post-RRCSetupComplete tracking */
    ctx->rrc_setup_complete_ms = 0;
    ctx->post_setup_pdu_count = 0;
    ctx->waiting_core_response = false;

    /* Configure RAN transport from config — start deferred to radio ON */
    if (cfg->ran.gnb_address[0]) {
        uint16_t port = cfg->ran.gnb_port ? cfg->ran.gnb_port : 4997;
        const char *addrs[1] = { cfg->ran.gnb_address };
        if (ue_ran_transport_configure(&ctx->ran, addrs, 1, port) == 0) {
            LOG_INF(RAN, "configured gNB endpoint %s:%u (start deferred to radio ON)",
                    cfg->ran.gnb_address, port);
        } else {
            LOG_ERR(RAN, "RAN transport configure failed for %s:%u",
                    cfg->ran.gnb_address, port);
        }
    } else {
        LOG_WRN(RAN, "no gNB address configured — uplink will be unavailable");
    }

    /* Wire network adapter to the real RAN transport. */
    ue_network_adapter_set_transport(&ctx->ran);
    ue_network_adapter_set_security_ctx(&ctx->nas_sec);
    LOG_INF(ENGINE, "backend mode: REAL");

    ue_context_refresh_snapshot(ctx);
    ctx->changed_flags = UE_ENGINE_CHANGED_IDENT |
                         UE_ENGINE_CHANGED_OPERATOR |
                         UE_ENGINE_CHANGED_DNN |
                         UE_ENGINE_CHANGED_IP |
                         UE_ENGINE_CHANGED_MM |
                         UE_ENGINE_CHANGED_SM;
    return 0;
}

void ue_context_refresh_snapshot(struct ue_context *ctx)
{
    struct ue_engine_snapshot *s;

    if (!ctx)
        return;

    s = &ctx->snapshot;
    memset(s, 0, sizeof(*s));

    s->running = ctx->running;
    s->radio_on = ctx->radio_on;
    s->sim_ready = ctx->sim_ready;
    s->mm_state = ctx->mm.state;
    s->sm_state = ctx->sm.state;
    s->mm_procedure = ctx->mm.procedure;
    s->sm_procedure = ctx->sm.procedure;
    s->mm_proc_step = ctx->mm.proc_step;
    s->sm_proc_step = ctx->sm.proc_step;
    s->mm_last_cause = ctx->mm.last_cause;
    s->sm_last_cause = ctx->sm.last_cause;
    s->mm_last_reject_class = ctx->mm.last_reject_class;
    s->sm_last_reject_class = ctx->sm.last_reject_class;
    s->mm_last_reject_cause_code = ctx->mm.last_reject_cause_code;
    s->sm_last_reject_cause_code = ctx->sm.last_reject_cause_code;
    s->mm_registration_attempt_id = ctx->mm.registration_attempt_id;
    s->sm_establishment_attempt_id = ctx->sm.establishment_attempt_id;
    s->mm_pending_reg_type = (uint32_t)ctx->mm.pending_reg_type;
    s->mm_pending_reg_trigger = (uint32_t)ctx->mm.pending_reg_trigger;
    snprintf(s->mm_last_assigned_guti, sizeof(s->mm_last_assigned_guti), "%s",
             ctx->mm.last_assigned_guti);
    s->session_id = ctx->sm.session_id;

    snprintf(s->active_dnn, sizeof(s->active_dnn), "%s", ctx->sm.active_dnn);
    snprintf(s->imei, sizeof(s->imei), "%s", ctx->cfg.device.imei);
    snprintf(s->imsi, sizeof(s->imsi), "%s", ctx->cfg.sim.imsi);
    snprintf(s->iccid, sizeof(s->iccid), "%s", ctx->cfg.sim.iccid);
    snprintf(s->manufacturer, sizeof(s->manufacturer), "%s",
             ctx->cfg.device.manufacturer);
    snprintf(s->model, sizeof(s->model), "%s", ctx->cfg.device.model);
    snprintf(s->firmware, sizeof(s->firmware), "%s", ctx->cfg.device.firmware);
    snprintf(s->serial, sizeof(s->serial), "%s", ctx->cfg.device.serial);

    snprintf(s->plmn, sizeof(s->plmn), "%s%s",
             ctx->cfg.network.mcc, ctx->cfg.network.mnc);
    snprintf(s->operator_name, sizeof(s->operator_name), "%s",
             ctx->cfg.network.operator_long);

    if (ctx->sm.state == UE_SM_ACTIVE)
        s->ip = ctx->sm.ip;
}
