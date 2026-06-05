#include "ue_engine.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../common/log.h"
#include "ue_mm.h"
#include "ue_nas_decode.h"
#include "ue_nas_encode.h"
#include "ue_nas_security.h"
#include "ue_ran_transport.h"
#include "ue_rrc.h"
#include "ue_sm.h"
#include "ue_up.h"

int ue_engine_init(struct ue_engine *engine,
                   const struct ue_instance_config *cfg,
                   uint32_t ue_id)
{
    if (!engine)
        return -1;
    return ue_context_init_from_config(&engine->ctx, ue_id, cfg);
}

void ue_engine_deinit(struct ue_engine *engine)
{
    if (!engine)
        return;
    ue_up_deinit(&engine->ctx.up);
    ue_ran_transport_deinit(&engine->ctx.ran);
    memset(engine, 0, sizeof(*engine));
}

int ue_engine_start(struct ue_engine *engine)
{
    if (!engine)
        return -1;
    engine->ctx.running = true;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_stop(struct ue_engine *engine)
{
    if (!engine)
        return -1;
    engine->ctx.running = false;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

/*
 * Send a NAS PDU uplink, wrapped in RRC ULInformationTransfer.
 *
 * integrity_only: when true, send SMC with
 * INTEGRITY_PROTECTED_CIPHERED_NEW_CTX (0x04), matching UERANSIM behavior.
 */
static int engine_send_nas_uplink(struct ue_context *ctx,
                                  const uint8_t *nas_pdu, int nas_len,
                                  bool integrity_only)
{
    uint8_t secured_buf[8192 + 64];
    uint8_t rrc_buf[8192 + 64];
    const uint8_t *send_pdu = nas_pdu;
    int send_len = nas_len;
    int rrc_len;

    if (nas_len <= 0)
        return -1;

    if (ctx->nas_sec.active) {
        uint8_t sht = integrity_only
                      ? NAS_SHT_INTEGRITY_PROTECTED_CIPHERED_NEW_CTX
                      : NAS_SHT_INTEGRITY_PROTECTED_CIPHERED;
        send_len = ue_nas_security_protect_with_sht(secured_buf, sizeof(secured_buf),
                                                    &ctx->nas_sec,
                                                    nas_pdu, (size_t)nas_len,
                                                    sht);
        if (send_len <= 0)
            return -1;
        send_pdu = secured_buf;
    }

    rrc_len = ue_rrc_encode_ul_info_transfer(rrc_buf, sizeof(rrc_buf),
                                             send_pdu, (size_t)send_len);
    if (rrc_len <= 0)
        return -1;

    LOG_TRC(NAS, "NAS UL send %d bytes (protected=%s)", nas_len, ctx->nas_sec.active ? "yes" : "no");
    {
        size_t i;
        size_t dump = (size_t)send_len < 120 ? (size_t)send_len : 120;
        char hex[640] = "";
        int hpos = 0;
        for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                             "%s%02x", i ? " " : "", send_pdu[i]);
        LOG_TRC(NAS, "NAS UL payload len=%d hex=%s%s",
                send_len, hex, (size_t)send_len > dump ? " ..." : "");
    }
    return ue_ran_transport_send_nas_pdu(&ctx->ran,
                                         rrc_buf, (size_t)rrc_len,
                                         UE_RRC_CHANNEL_UL_DCCH);
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

static int parse_hex_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;

    if (!hex || !out)
        return -1;
    if (strlen(hex) < out_len * 2)
        return -1;

    for (i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/*
 * Map the MM pending registration intent to a 5GS registration type:
 *   1 = initial, 2 = mobility update, 3 = periodic update.
 */
static uint8_t engine_reg_type(const struct ue_mm_ctx *mm)
{
    if (mm->pending_reg_type == UE_MM_REG_INITIAL)
        return 1;
    if (mm->pending_reg_trigger == UE_MM_REG_TRIGGER_PERIODIC_UPDATE)
        return 3;
    return 2;
}

/*
 * ngKSI to advertise in a Registration Request: the network-assigned key set
 * identifier for mobility/periodic updates with an existing security context,
 * otherwise 7 ("no key available") for initial registration.
 */
static uint8_t engine_reg_ngksi(const struct ue_context *ctx)
{
    if (ctx->reg_ngksi_valid && engine_reg_type(&ctx->mm) != 1)
        return ctx->reg_ngksi;
    return 7;
}

static void engine_reset_rrc_tracking(struct ue_context *ctx)
{
    ctx->rrc_state = UE_RRC_IDLE;
    ctx->rrc_setup_request_ms = 0;
    ctx->rrc_setup_complete_ms = 0;
    ctx->post_setup_pdu_count = 0;
    ctx->waiting_core_response = false;
}

static void engine_clear_nas_identity_context(struct ue_context *ctx)
{
    memset(&ctx->nas_sec, 0, sizeof(ctx->nas_sec));
    ctx->nas_sec.int_alg = UE_NIA0;
    ctx->nas_sec.enc_alg = UE_NEA0;
    ctx->nas_sec.bearer = 1;
    ctx->nas_sec.ngksi = 7;
    memset(&ctx->nas_sec_non_current, 0, sizeof(ctx->nas_sec_non_current));
    ctx->nas_sec_non_current_valid = false;
    ctx->dl_sec_hdr_valid = false;
    ctx->smc_last_valid = false;
    ctx->smc_last_inner_len = 0;
    ctx->smc_last_payload_len = 0;
    memset(ctx->guti, 0, sizeof(ctx->guti));
    ctx->guti_len = 0;
    memset(ctx->auth_sqn_ms, 0, sizeof(ctx->auth_sqn_ms));
    ctx->auth_sqn_ms_valid = false;
    ctx->reg_ngksi = 7;
    ctx->reg_ngksi_valid = false;
    ctx->t3512_seconds = 0;
    ctx->mm.last_assigned_guti[0] = '\0';
}

static void engine_clear_sm_runtime(struct ue_context *ctx)
{
    ctx->sm.session_id = 0;
    memset(&ctx->sm.ip, 0, sizeof(ctx->sm.ip));
    ctx->sm.pti = 0;
    ctx->sm.next_pti = 0;
    ctx->sm.est_retx_count = 0;
    ctx->sm.establishment_attempt_id = 0;
    ctx->sm.next_step_deadline_ms = 0;
    ctx->sm.connect_requested = false;
    ctx->sm.disconnect_requested = false;
}

static void engine_forget_network_context(struct ue_context *ctx)
{
    if (!ctx)
        return;
    engine_reset_rrc_tracking(ctx);
    engine_clear_nas_identity_context(ctx);
    engine_clear_sm_runtime(ctx);
    ue_ran_transport_refresh_sti(&ctx->ran);

    /*
     * Drop the internal IMS PDU session too. The next state_bridge_poll then
     * propagates ims_pdu_active=false to ims_service (set_pdu_active), which
     * tears down SIP registration. Without this, IMS state survived a radio
     * OFF/ON cycle (stale registration, stale up session on ims_psi).
     */
    ue_up_unbind_session_psi(&ctx->up, ctx->ims_psi);
    ctx->ims_pdu_requested = false;
    ctx->ims_pdu_establishing = false;
    ctx->ims_pdu_active = false;
    ctx->ims_has_pcscf = false;
    memset(ctx->ims_pcscf_ipv4, 0, sizeof(ctx->ims_pcscf_ipv4));
    memset(&ctx->ims_ip, 0, sizeof(ctx->ims_ip));
}

static void engine_process_nas_event(struct ue_context *ctx,
                                     const struct ue_nas_event *event);

static int verify_smc_new_context_mac(struct ue_context *ctx,
                                      const struct ue_nas_security_ctx *base_ctx,
                                      const uint8_t *smc_payload,
                                      size_t smc_payload_len,
                                      const uint8_t *smc_inner,
                                      size_t smc_inner_len,
                                      uint8_t int_alg,
                                      uint8_t enc_alg,
                                      uint8_t ngksi,
                                      struct ue_nas_keys *out_keys,
                                      bool *out_used_count0)
{
    struct ue_nas_security_ctx tmp;
    uint32_t mac_calc;
    uint32_t mac_rx;
    uint8_t mac_msg[1 + 256];
    size_t mac_msg_len;

    if (!ctx || !base_ctx || !smc_payload || smc_payload_len == 0 || !out_keys || !out_used_count0)
        return -1;
    if (!ctx->dl_sec_hdr_valid ||
        ctx->dl_sec_hdr_sht != NAS_SHT_INTEGRITY_PROTECTED_NEW_CTX)
        return -1;
    if (smc_payload_len > sizeof(mac_msg) - 1)
        return -1;

    *out_keys = base_ctx->keys;
    if (ue_nas_derive_knas_from_kamf(base_ctx->keys.kamf,
                                     int_alg,
                                     enc_alg,
                                     out_keys->knas_int,
                                     out_keys->knas_enc) < 0)
        return -1;

    tmp = *base_ctx;
    tmp.int_alg = (enum ue_nas_integrity_alg)int_alg;
    tmp.enc_alg = (enum ue_nas_ciphering_alg)enc_alg;
    tmp.bearer = 1;
    tmp.ngksi = ngksi;
    tmp.keys = *out_keys;
    /* Do not log key material (kamf/knas_*), even at trace level. */
    LOG_TRC(NAS, "SMC verify ctx: ngksi=%u int_alg=%u enc_alg=%u",
            (unsigned)ngksi, (unsigned)int_alg, (unsigned)enc_alg);

    mac_rx = ctx->dl_sec_hdr_mac;
    tmp.dl_count.sqn = ctx->dl_sec_hdr_sqn;
    mac_msg[0] = ctx->dl_sec_hdr_sqn;
    memcpy(mac_msg + 1, smc_payload, smc_payload_len);
    mac_msg_len = smc_payload_len + 1;
    mac_calc = ue_nas_compute_mac(tmp.int_alg,
                                  ue_nas_count_value(&tmp.dl_count),
                                  tmp.bearer,
                                  1,
                                  tmp.keys.knas_int,
                                  mac_msg,
                                  mac_msg_len);
    LOG_TRC(NAS, "SMC verify new-ctx payload: rx=0x%08x calc=0x%08x count=0x%08x",
            (unsigned)mac_rx, (unsigned)mac_calc,
            (unsigned)ue_nas_count_value(&tmp.dl_count));

    if (smc_inner && smc_inner_len > 0) {
        uint8_t inner_msg[1 + 256];
        uint32_t mac_inner;
        if (smc_inner_len > sizeof(inner_msg) - 1)
            return -1;
        inner_msg[0] = ctx->dl_sec_hdr_sqn;
        memcpy(inner_msg + 1, smc_inner, smc_inner_len);
        mac_inner = ue_nas_compute_mac(tmp.int_alg,
                                       ue_nas_count_value(&tmp.dl_count),
                                       tmp.bearer,
                                       1,
                                       tmp.keys.knas_int,
                                       inner_msg,
                                       smc_inner_len + 1);
        LOG_TRC(NAS, "SMC verify new-ctx inner:   rx=0x%08x calc=0x%08x count=0x%08x",
                (unsigned)mac_rx, (unsigned)mac_inner,
                (unsigned)ue_nas_count_value(&tmp.dl_count));
    }

    if (mac_calc == mac_rx) {
        *out_used_count0 = false;
        return 0;
    }

    tmp.dl_count.overflow = 0;
    tmp.dl_count.sqn = ctx->dl_sec_hdr_sqn;
    mac_calc = ue_nas_compute_mac(tmp.int_alg,
                                  ue_nas_count_value(&tmp.dl_count),
                                  tmp.bearer,
                                  1,
                                  tmp.keys.knas_int,
                                  mac_msg,
                                  mac_msg_len);
    LOG_TRC(NAS, "SMC verify new-ctx payload fallback COUNT=0: rx=0x%08x calc=0x%08x count=0x%08x",
            (unsigned)mac_rx, (unsigned)mac_calc,
            (unsigned)ue_nas_count_value(&tmp.dl_count));

    if (smc_inner && smc_inner_len > 0) {
        uint8_t inner_msg[1 + 256];
        uint32_t mac_inner;
        if (smc_inner_len > sizeof(inner_msg) - 1)
            return -1;
        inner_msg[0] = ctx->dl_sec_hdr_sqn;
        memcpy(inner_msg + 1, smc_inner, smc_inner_len);
        mac_inner = ue_nas_compute_mac(tmp.int_alg,
                                       ue_nas_count_value(&tmp.dl_count),
                                       tmp.bearer,
                                       1,
                                       tmp.keys.knas_int,
                                       inner_msg,
                                       smc_inner_len + 1);
        LOG_TRC(NAS, "SMC verify new-ctx inner fallback COUNT=0:   rx=0x%08x calc=0x%08x count=0x%08x",
                (unsigned)mac_rx, (unsigned)mac_inner,
                (unsigned)ue_nas_count_value(&tmp.dl_count));
    }
    if (mac_calc == mac_rx) {
        *out_used_count0 = true;
        return 0;
    }

    return -1;
}

static int decode_and_process_nas(struct ue_context *ctx,
                                  uint8_t *nas_pdu, size_t nas_len)
{
    struct ue_nas_event event;
    const uint8_t *plain = nas_pdu;
    size_t plain_len = nas_len;

    if (nas_len >= 2 && nas_pdu[0] == NAS_EPD_5GMM &&
        nas_pdu[1] != NAS_SHT_NOT_PROTECTED) {
        uint8_t sht = nas_pdu[1];
        LOG_DBG(NAS, "NAS protected DL received: len=%zu security_header_type=0x%02x",
                nas_len, sht);

        /*
         * Dedicated handling for SHT=0x03 (integrity protected with new context).
         * Align with UERANSIM behavior: parse security envelope and decode inner
         * plain NAS (expected: SecurityModeCommand), instead of generic unprotect.
         */
        if (sht == NAS_SHT_INTEGRITY_PROTECTED_NEW_CTX) {
            struct ue_nas_sec_header_info hdr;
            const uint8_t *inner = NULL;
            size_t inner_len = 0;

            if (ue_nas_security_unwrap_parse_only(nas_pdu, nas_len, &hdr,
                                                  &inner, &inner_len) < 0) {
                LOG_WRN(NAS, "NAS protected DL SHT=0x03 parse-only unwrap failed, dropping");
                return -1;
            }

            LOG_TRC(NAS, "NAS protected DL SHT=0x03 header: mac=0x%08x sqn=%u",
                    hdr.mac, hdr.sqn);
            ctx->dl_sec_hdr_valid = true;
            ctx->dl_sec_hdr_sht = hdr.sht;
            ctx->dl_sec_hdr_mac = hdr.mac;
            ctx->dl_sec_hdr_sqn = hdr.sqn;
            if (nas_len > 7 && (nas_len - 7) <= sizeof(ctx->smc_last_payload)) {
                memcpy(ctx->smc_last_payload, nas_pdu + 7, nas_len - 7);
                ctx->smc_last_payload_len = nas_len - 7;
            } else {
                ctx->smc_last_payload_len = 0;
            }
            if (inner_len <= sizeof(ctx->smc_last_inner)) {
                memcpy(ctx->smc_last_inner, inner, inner_len);
                ctx->smc_last_inner_len = inner_len;
            } else {
                ctx->smc_last_inner_len = 0;
            }
            {
                size_t i;
                char hex[512] = "";
                int hpos = 0;
                size_t dump = inner_len < 96 ? inner_len : 96;
                for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
                    hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                                     "%s%02x", i ? " " : "", inner[i]);
                LOG_TRC(NAS, "NAS protected DL SHT=0x03 inner len=%zu hex=%s%s",
                        inner_len, hex, inner_len > dump ? " ..." : "");
            }

            plain = inner;
            plain_len = inner_len;
        } else if (ctx->nas_sec.active) {
            if (ue_nas_security_unprotect(nas_pdu, nas_len, &ctx->nas_sec,
                                          &plain, &plain_len) < 0) {
                LOG_WRN(NAS, "NAS protected DL unprotect failed (active ctx), dropping");
                return -1;
            }
            ctx->dl_sec_hdr_valid = true;
            ctx->dl_sec_hdr_sht = sht;
            ctx->dl_sec_hdr_mac = ((uint32_t)nas_pdu[2] << 24) |
                                  ((uint32_t)nas_pdu[3] << 16) |
                                  ((uint32_t)nas_pdu[4] << 8) |
                                  (uint32_t)nas_pdu[5];
            ctx->dl_sec_hdr_sqn = nas_pdu[6];
        } else {
            LOG_WRN(NAS, "NAS protected DL unsupported without active ctx: sht=0x%02x", sht);
            return -1;
        }
    }

    if (ue_nas_decode_event(plain, plain_len, &event) < 0)
        return -1;

    LOG_TRC(NAS, "NAS PDU decoded, security %s", ctx->nas_sec.active ? "active" : "inactive");
    LOG_DBG(NAS, "NAS event decoded: type=%d epd=0x%02x msg=0x%02x len=%zu",
            event.type, event.raw_epd, event.raw_msg_type, plain_len);
    engine_process_nas_event(ctx, &event);
    return 0;
}

/*
 * Process a single decoded NAS event and inject into ue_mm or ue_sm.
 *
 * This is the real control plane injection point.
 * UERANSIM anchor:
 *   - src/ue/nas/mm/messaging.cpp : receiveMmMessage dispatch
 *   - src/ue/nas/mm/register.cpp  : receiveRegistrationAccept/Reject
 *   - src/ue/nas/sm/establishment.cpp : receiveEstablishmentAccept/Reject
 *   - src/ue/nas/sm/release.cpp   : receiveReleaseCommand
 */
static void engine_process_nas_event(struct ue_context *ctx,
                                     const struct ue_nas_event *event)
{
    enum ue_mm_state mm_before;
    enum ue_sm_state sm_before;
    enum ue_mm_procedure mm_proc_before;
    enum ue_sm_procedure sm_proc_before;
    enum ue_mm_proc_step mm_step_before;
    enum ue_sm_proc_step sm_step_before;

    mm_before = ctx->mm.state;
    sm_before = ctx->sm.state;
    mm_proc_before = ctx->mm.procedure;
    sm_proc_before = ctx->sm.procedure;
    mm_step_before = ctx->mm.proc_step;
    sm_step_before = ctx->sm.proc_step;

    switch (event->type) {
    case UE_NAS_EVENT_REGISTRATION_ACCEPT:
        /*
         * Real registration accepted by the network. Drive MM to
         * REGISTERED_HOME. If the Accept carried a 5G-GUTI, store it (for reuse
         * as the mobile identity in later registrations) and acknowledge it
         * with a REGISTRATION COMPLETE (UERANSIM register.cpp:422).
         */
        LOG_INF(MM, "Registration Accept received");
        ctx->waiting_core_response = false;
        ue_mm_on_registration_accept(&ctx->mm);

        if (event->has_guti && event->guti_len > 0 &&
            event->guti_len <= sizeof(ctx->guti)) {
            size_t gi;
            int hp = 0;
            memcpy(ctx->guti, event->guti, event->guti_len);
            ctx->guti_len = event->guti_len;
            for (gi = 0; gi < event->guti_len &&
                         hp < (int)sizeof(ctx->mm.last_assigned_guti) - 2; gi++)
                hp += snprintf(ctx->mm.last_assigned_guti + hp,
                               sizeof(ctx->mm.last_assigned_guti) - (size_t)hp,
                               "%02x", event->guti[gi]);

            {
                uint8_t nas_buf[16];
                int nas_len = ue_nas_encode_registration_complete(nas_buf, sizeof(nas_buf));
                if (nas_len > 0) {
                    LOG_INF(NAS, "Registration Complete sent (ack 5G-GUTI %u bytes)",
                            (unsigned)event->guti_len);
                    engine_send_nas_uplink(ctx, nas_buf, nas_len, false);
                }
            }
        }

        if (event->has_t3512)
            ctx->t3512_seconds = event->t3512_seconds;
        break;

    case UE_NAS_EVENT_REGISTRATION_REJECT: {
        /*
         * Real registration rejected by the network.
         * Map 5GMM cause to our reject cause enum.
         */
        enum ue_mm_reg_reject_cause cause = UE_MM_REG_REJECT_CONGESTION;
        switch (event->mm_cause) {
        case 3:  cause = UE_MM_REG_REJECT_ILLEGAL_UE; break;
        case 11: cause = UE_MM_REG_REJECT_PLMN_NOT_ALLOWED; break;
        case 12: cause = UE_MM_REG_REJECT_TA_NOT_ALLOWED; break;
        case 22: cause = UE_MM_REG_REJECT_CONGESTION; break;
        default: cause = UE_MM_REG_REJECT_CONGESTION; break;
        }
        LOG_WRN(MM, "Registration Reject cause=%u", event->mm_cause);
        ctx->waiting_core_response = false;
        ue_mm_on_registration_reject(&ctx->mm, cause);
        break;
    }

    case UE_NAS_EVENT_PDU_SESSION_EST_ACCEPT:
        /*
         * PDU session established by the network.
         * Extract IP config and bind to user plane.
         */
        LOG_INF(SM, "PDU Session Accept psi=%u pti=%u", event->psi, event->pti);
        /*
         * Internal IMS PDU session (SMS over IMS): not host-visible, bound on
         * its own PSI and handed to ims_service. It is tracked independently of
         * the host SM state machine.
         */
        if (ctx->ims_pdu_establishing && event->psi == ctx->ims_psi &&
            event->pti == ctx->ims_pti) {
            if (event->has_pdu_address && event->pdu_addr_type == 1)
                memcpy(ctx->ims_ip.ipv4_addr, event->ipv4_addr, 4);
            if (event->has_dns)
                memcpy(ctx->ims_ip.dns1, event->dns_ipv4, 4);
            if (event->has_pcscf) {
                memcpy(ctx->ims_pcscf_ipv4, event->pcscf_ipv4, 4);
                ctx->ims_has_pcscf = true;
            }
            ctx->ims_ip.mtu = ctx->ims_ip.mtu ? ctx->ims_ip.mtu : 1500;
            ctx->ims_pdu_establishing = false;
            ctx->ims_pdu_active = true;
            ue_up_bind_session_ex(&ctx->up, event->psi, "ims", "ipv4",
                                  &ctx->ims_ip, false);
            LOG_INF(SM, "IMS PDU Session active psi=%u", event->psi);
            break;
        }
        /* checkPtiAndPsi: an Accept is only valid while we are establishing. */
        if (ctx->sm.state != UE_SM_ESTABLISHING) {
            uint8_t sbuf[16];
            int slen = ue_nas_encode_sm_status(sbuf, sizeof(sbuf),
                                               event->psi, event->pti,
                                               NAS_5GSM_CAUSE_MSG_INCOMPAT_STATE);
            LOG_WRN(SM, "PDU Session Accept not expected (sm_state=%d), sending 5GSM STATUS #98",
                    ctx->sm.state);
            if (slen > 0)
                engine_send_nas_uplink(ctx, sbuf, slen, false);
            break;
        }
        if (event->has_pdu_address && event->pdu_addr_type == 1) {
            memcpy(ctx->sm.ip.ipv4_addr, event->ipv4_addr, 4);
        }
        if (event->has_dns) {
            memcpy(ctx->sm.ip.dns1, event->dns_ipv4, 4);
        }
        ctx->sm.session_id = event->psi;
        ue_sm_on_pdu_session_established(&ctx->sm);

        /* Bind user plane data path */
        if (ctx->sm.state == UE_SM_ACTIVE) {
            ue_up_bind_session(&ctx->up,
                               event->psi ? event->psi : 1,
                               ctx->sm.active_dnn,
                               ctx->sm.pdu_type,
                               &ctx->sm.ip);
        }
        break;

    case UE_NAS_EVENT_PDU_SESSION_EST_REJECT: {
        enum ue_sm_pdu_reject_cause cause = UE_SM_PDU_REJECT_INSUFFICIENT_RESOURCES;
        LOG_WRN(SM, "PDU Session Reject cause=%u pti=%u", event->sm_cause, event->pti);
        if (ctx->ims_pdu_establishing && event->psi == ctx->ims_psi &&
            event->pti == ctx->ims_pti) {
            ctx->ims_pdu_establishing = false;
            ctx->ims_pdu_requested = false;
            ctx->ims_pdu_active = false;
            LOG_WRN(SM, "IMS PDU Session Reject cause=%u", event->sm_cause);
            break;
        }
        if (ctx->sm.state != UE_SM_ESTABLISHING) {
            uint8_t sbuf[16];
            int slen = ue_nas_encode_sm_status(sbuf, sizeof(sbuf),
                                               event->psi, event->pti,
                                               NAS_5GSM_CAUSE_MSG_INCOMPAT_STATE);
            LOG_WRN(SM, "PDU Session Reject not expected (sm_state=%d), sending 5GSM STATUS #98",
                    ctx->sm.state);
            if (slen > 0)
                engine_send_nas_uplink(ctx, sbuf, slen, false);
            break;
        }
        switch (event->sm_cause) {
        case 26: cause = UE_SM_PDU_REJECT_INSUFFICIENT_RESOURCES; break;
        case 27: cause = UE_SM_PDU_REJECT_MISSING_DNN; break;
        case 28: cause = UE_SM_PDU_REJECT_UNKNOWN_PDU_SESSION_TYPE; break;
        default: cause = UE_SM_PDU_REJECT_INSUFFICIENT_RESOURCES; break;
        }
        ue_sm_on_pdu_session_reject(&ctx->sm, cause);
        break;
    }

    case UE_NAS_EVENT_PDU_SESSION_RELEASE_CMD: {
        /*
         * Network sent PDU SESSION RELEASE COMMAND. Acknowledge with a
         * RELEASE COMPLETE (echoing PSI/PTI), then tear down the session.
         * UERANSIM anchor: release.cpp receiveReleaseCommand -> sendReleaseComplete.
         */
        uint8_t nas_buf[16];
        int nas_len;

        LOG_INF(SM, "PDU Session Release Command received psi=%u pti=%u",
                event->psi, event->pti);

        nas_len = ue_nas_encode_pdu_session_release_complete(
            nas_buf, sizeof(nas_buf), event->psi, event->pti);
        if (nas_len > 0) {
            LOG_INF(SM, "PDU Session Release Complete sent");
            engine_send_nas_uplink(ctx, nas_buf, nas_len, false);
        }

        if (ctx->ims_pdu_active && event->psi == ctx->ims_psi) {
            ctx->ims_pdu_active = false;
            ctx->ims_pdu_requested = false;
            ctx->ims_pdu_establishing = false;
            ue_up_unbind_session_psi(&ctx->up, ctx->ims_psi);
            LOG_INF(SM, "IMS PDU Session released psi=%u", event->psi);
            break;
        }

        ue_up_unbind_session(&ctx->up);
        ue_sm_on_pdu_session_released(&ctx->sm);
        break;
    }

    case UE_NAS_EVENT_AUTHENTICATION_REQUEST: {
        uint8_t k[16], opc[16], amf[2], sqn[6], autn_mac[8], calc_autn_mac[8];
        uint8_t nas_buf[64];
        const uint8_t *abba = NULL;
        size_t abba_len = 0;
        uint8_t sqn_xor_ak[6];
        char snn[96], supi[48];
        int nas_len;
        int i;

        LOG_INF(NAS, "Authentication Request received");
        if (!event->has_auth_rand || !event->has_auth_autn)
            break;

        if (parse_hex_bytes(ctx->cfg.sim.key, k, sizeof(k)) < 0 ||
            parse_hex_bytes(ctx->cfg.sim.opc, opc, sizeof(opc)) < 0 ||
            parse_hex_bytes(ctx->cfg.sim.amf, amf, sizeof(amf)) < 0)
            break;

        memcpy(ctx->nas_sec.rand, event->auth_rand, 16);
        memcpy(ctx->nas_sec.sqn_xor_ak, event->auth_autn, 6);
        if (event->has_auth_abba && event->auth_abba_len <= sizeof(ctx->nas_sec.abba)) {
            memcpy(ctx->nas_sec.abba, event->auth_abba, event->auth_abba_len);
            ctx->nas_sec.abba_len = event->auth_abba_len;
        } else {
            ctx->nas_sec.abba[0] = 0x00;
            ctx->nas_sec.abba[1] = 0x00;
            ctx->nas_sec.abba_len = 2;
        }
        abba = ctx->nas_sec.abba;
        abba_len = ctx->nas_sec.abba_len;

        memset(sqn, 0, sizeof(sqn));
        if (ue_milenage_compute(opc, k, event->auth_rand, sqn, amf,
                                &ctx->nas_sec.milenage) < 0)
            break;

        memcpy(sqn_xor_ak, event->auth_autn, 6);
        for (i = 0; i < 6; i++)
            sqn[i] = sqn_xor_ak[i] ^ ctx->nas_sec.milenage.ak[i];

        if (ue_milenage_compute(opc, k, event->auth_rand, sqn, amf,
                                &ctx->nas_sec.milenage) < 0)
            break;

        memcpy(calc_autn_mac, ctx->nas_sec.milenage.mac_a, 8);
        memcpy(autn_mac, event->auth_autn + 8, 8);
        if (memcmp(calc_autn_mac, autn_mac, 8) != 0) {
            /* XMAC != MAC → Authentication Failure, cause MAC failure (#20). */
            uint8_t fbuf[16];
            int flen = ue_nas_encode_auth_failure(fbuf, sizeof(fbuf), 0x14, NULL, 0);
            LOG_WRN(NAS, "Authentication Request: MAC failure, sending Auth Failure #20");
            if (flen > 0)
                engine_send_nas_uplink(ctx, fbuf, flen, false);
            break;
        }

        /*
         * SQN range check (TS 33.102 §6.3.5). If our highest accepted SQN is
         * ahead of the received SQN, the network is behind: reply with
         * Authentication Failure, cause synch failure (#21), carrying an AUTS
         * resync token so the network can re-synchronise.
         */
        if (ctx->auth_sqn_ms_valid && memcmp(sqn, ctx->auth_sqn_ms, 6) < 0) {
            struct ue_milenage_result rs;
            uint8_t amf_zero[2] = { 0x00, 0x00 };
            uint8_t auts[14];
            uint8_t fbuf[32];
            int flen;
            int j;

            if (ue_milenage_compute(opc, k, event->auth_rand,
                                    ctx->auth_sqn_ms, amf_zero, &rs) == 0) {
                for (j = 0; j < 6; j++)
                    auts[j] = (uint8_t)(ctx->auth_sqn_ms[j] ^ rs.ak_star[j]);
                memcpy(auts + 6, rs.mac_s, 8);
                flen = ue_nas_encode_auth_failure(fbuf, sizeof(fbuf), 0x15,
                                                  auts, sizeof(auts));
                LOG_WRN(NAS, "Authentication Request: SQN behind, sending Auth Failure #21 (synch) + AUTS");
                if (flen > 0)
                    engine_send_nas_uplink(ctx, fbuf, flen, false);
            }
            break;
        }

        /* Accept this challenge: record the highest accepted SQN and ngKSI. */
        memcpy(ctx->auth_sqn_ms, sqn, 6);
        ctx->auth_sqn_ms_valid = true;
        if (event->has_ngksi) {
            ctx->reg_ngksi = event->ngksi;
            ctx->reg_ngksi_valid = true;
        }

        snprintf(snn, sizeof(snn), "5G:mnc%03d.mcc%03d.3gppnetwork.org",
                 atoi(ctx->cfg.network.mnc), atoi(ctx->cfg.network.mcc));
        snprintf(supi, sizeof(supi), "%s", ctx->cfg.sim.imsi);

        if (ue_nas_derive_keys(ctx->nas_sec.milenage.ck,
                               ctx->nas_sec.milenage.ik,
                               ctx->nas_sec.milenage.ak,
                               event->auth_rand,
                               ctx->nas_sec.milenage.res,
                               sqn,
                               snn,
                               supi,
                               abba, abba_len,
                               UE_NIA2, UE_NEA0,
                               &ctx->nas_sec.keys) < 0)
            break;

        ctx->nas_sec_non_current = ctx->nas_sec;
        ctx->nas_sec_non_current.active = true;
        ctx->nas_sec_non_current.int_alg = UE_NIA2;
        ctx->nas_sec_non_current.enc_alg = UE_NEA0;
        ctx->nas_sec_non_current.bearer = 1;
        /*
         * Key the new (non-current) security context with the ngKSI the network
         * assigned in this Authentication Request, not a hardcoded 0. The AMF
         * echoes the same ngKSI in the Security Mode Command, where we look the
         * context up by ngKSI. The first registration after boot happens to use
         * ngKSI=0, but a re-registration (e.g. after radio off/on) uses ngKSI=1,
         * which previously failed with "context not found for ngKSI=1".
         */
        ctx->nas_sec_non_current.ngksi = event->has_ngksi ? event->ngksi : 0;
        ctx->nas_sec_non_current.ul_count.overflow = 0;
        ctx->nas_sec_non_current.ul_count.sqn = 0;
        ctx->nas_sec_non_current.dl_count.overflow = 0;
        ctx->nas_sec_non_current.dl_count.sqn = 0;
        ctx->nas_sec_non_current_valid = true;

        nas_len = ue_nas_encode_auth_response(nas_buf, sizeof(nas_buf),
                                              ctx->nas_sec.keys.res_star,
                                              sizeof(ctx->nas_sec.keys.res_star));
        if (nas_len > 0) {
            LOG_INF(NAS, "Authentication Response sent (RES*=%zu bytes)", sizeof(ctx->nas_sec.keys.res_star));
            engine_send_nas_uplink(ctx, nas_buf, nas_len, false);
        }
        break;
    }

    case UE_NAS_EVENT_SECURITY_MODE_COMMAND: {
        uint8_t int_alg = UE_NIA2;
        uint8_t enc_alg = UE_NEA0;
        uint8_t ngksi = 0;
        bool duplicate_smc = false;
        bool smc_mac_ok = false;
        bool smc_count0 = false;
        bool using_non_current = false;
        struct ue_nas_security_ctx *target_ctx = NULL;
        struct ue_nas_keys derived_keys;
        uint8_t reg_container[256];
        int reg_container_len = -1;
        uint8_t nas_buf[64];
        int nas_len;

        if (event->has_sec_algs) {
            enc_alg = event->sec_enc_alg;
            int_alg = event->sec_int_alg;
            if (enc_alg > UE_NEA2 || enc_alg == UE_NEA1)
                enc_alg = UE_NEA0;
            if (int_alg > UE_NIA2 || int_alg == UE_NIA1)
                int_alg = UE_NIA2;
        }
        if (event->has_ngksi)
            ngksi = event->ngksi;

        if (ctx->dl_sec_hdr_valid && ctx->dl_sec_hdr_sht == NAS_SHT_INTEGRITY_PROTECTED_NEW_CTX &&
            ctx->smc_last_valid &&
            ctx->smc_last_mac == ctx->dl_sec_hdr_mac &&
            ctx->smc_last_sqn == ctx->dl_sec_hdr_sqn &&
            ctx->smc_last_algs == (uint8_t)((enc_alg << 4) | int_alg) &&
            ctx->smc_last_ngksi == ngksi) {
            duplicate_smc = true;
            LOG_WRN(NAS, "Duplicate Security Mode Command detected (mac=0x%08x sqn=%u), sending idempotent response",
                    ctx->dl_sec_hdr_mac, ctx->dl_sec_hdr_sqn);
        }

        LOG_INF(NAS, "Security Mode Command received algos=0x%02x ngKSI=%u",
                (unsigned)(enc_alg << 4 | int_alg), event->has_ngksi ? event->ngksi : 0);
        LOG_DBG(NAS, "Security Mode Command key derivation ABBA len=%u",
                (unsigned)ctx->nas_sec.abba_len);

        if (ctx->nas_sec.active && ctx->nas_sec.ngksi == ngksi) {
            target_ctx = &ctx->nas_sec;
        } else if (ctx->nas_sec_non_current_valid &&
                   ctx->nas_sec_non_current.ngksi == ngksi) {
            target_ctx = &ctx->nas_sec_non_current;
            using_non_current = true;
        }

        if (!target_ctx) {
            LOG_WRN(NAS, "Security Mode Command context not found for ngKSI=%u, dropping",
                    (unsigned)ngksi);
            break;
        }

        if (!duplicate_smc &&
            verify_smc_new_context_mac(ctx,
                                       target_ctx,
                                       ctx->smc_last_payload,
                                       ctx->smc_last_payload_len,
                                       ctx->smc_last_inner,
                                       ctx->smc_last_inner_len,
                                       int_alg,
                                       enc_alg,
                                       ngksi,
                                       &derived_keys,
                                       &smc_count0) == 0) {
            smc_mac_ok = true;
        }

        if (duplicate_smc) {
            smc_mac_ok = true;
        }

        if (smc_mac_ok && !duplicate_smc) {
            target_ctx->keys = derived_keys;
            target_ctx->int_alg = (enum ue_nas_integrity_alg)int_alg;
            target_ctx->enc_alg = (enum ue_nas_ciphering_alg)enc_alg;
            target_ctx->bearer = 1;
            if (event->has_ngksi)
                target_ctx->ngksi = ngksi;
            if (smc_count0) {
                target_ctx->dl_count.overflow = 0;
                target_ctx->dl_count.sqn = 0;
            }
            target_ctx->active = true;
            if (using_non_current) {
                ctx->nas_sec = *target_ctx;
                ctx->nas_sec_non_current_valid = false;
                /* UERANSIM-style: reset UL count when taking non-current as current. */
                ctx->nas_sec.ul_count.overflow = 0;
                ctx->nas_sec.ul_count.sqn = 0;
            }
            ctx->nas_sec.active = true;
        } else if (!smc_mac_ok) {
            LOG_WRN(NAS, "Security Mode Command MAC validation failed with new context, not sending SMC Complete");
            break;
        }

        if (ctx->dl_sec_hdr_valid && ctx->dl_sec_hdr_sht == NAS_SHT_INTEGRITY_PROTECTED_NEW_CTX) {
            ctx->smc_last_valid = true;
            ctx->smc_last_mac = ctx->dl_sec_hdr_mac;
            ctx->smc_last_sqn = ctx->dl_sec_hdr_sqn;
            ctx->smc_last_algs = (uint8_t)((enc_alg << 4) | int_alg);
            ctx->smc_last_ngksi = ngksi;
        }

        reg_container_len = ue_nas_encode_registration_request(
            reg_container, sizeof(reg_container),
            ctx->cfg.sim.imsi,
            ctx->cfg.network.mcc,
            ctx->cfg.network.mnc,
            ctx->cfg.network.slice_sst,
            engine_reg_type(&ctx->mm),
            ctx->guti_len ? ctx->guti : NULL, ctx->guti_len,
            engine_reg_ngksi(ctx),
            0 /* complete initial NAS in SMC container */);
        if (reg_container_len > 0) {
            LOG_DBG(NAS, "Security Mode Complete includes NAS container len=%d",
                    reg_container_len);
        } else {
            LOG_WRN(NAS, "Security Mode Complete NAS container omitted (encode failed)");
        }

        nas_len = ue_nas_encode_security_mode_complete(nas_buf, sizeof(nas_buf),
                                                       reg_container_len > 0 ? reg_container : NULL,
                                                       reg_container_len > 0 ? (size_t)reg_container_len : 0);
        if (nas_len > 0) {
            LOG_INF(NAS, "Security Mode Complete sent");
            engine_send_nas_uplink(ctx, nas_buf, nas_len, true);
        }
        break;
    }

    case UE_NAS_EVENT_IDENTITY_REQUEST: {
        /*
         * Identity Request from the network (requesting SUCI).
         * Send Identity Response with our SUCI (IMSI in null scheme).
         */
        uint8_t nas_buf[64];
        int nas_len;

        LOG_INF(NAS, "Identity Request received");
        nas_len = ue_nas_encode_identity_response(nas_buf, sizeof(nas_buf),
                                                   ctx->cfg.sim.imsi,
                                                   ctx->cfg.network.mcc,
                                                   ctx->cfg.network.mnc);
        if (nas_len > 0)
            engine_send_nas_uplink(ctx, nas_buf, nas_len, false);
        break;
    }

    case UE_NAS_EVENT_CONFIG_UPDATE_COMMAND: {
        /*
         * Configuration Update Command. If the network requested
         * acknowledgement, reply with Configuration Update Complete
         * (UERANSIM: receiveConfigurationUpdate). The carried GUTI/TAI/NSSAI
         * parameters are not stored (see known simplifications).
         */
        LOG_INF(MM, "Configuration Update Command received (ack_requested=%d)",
                event->config_update_ack_requested);
        if (event->config_update_ack_requested) {
            uint8_t nas_buf[8];
            int nas_len = ue_nas_encode_configuration_update_complete(nas_buf, sizeof(nas_buf));
            if (nas_len > 0) {
                LOG_INF(NAS, "Configuration Update Complete sent");
                engine_send_nas_uplink(ctx, nas_buf, nas_len, false);
            }
        }
        break;
    }

    case UE_NAS_EVENT_UNKNOWN:
    case UE_NAS_EVENT_DL_NAS_TRANSPORT:
    default:
        break;
    }

    if (mm_before != ctx->mm.state ||
        mm_proc_before != ctx->mm.procedure ||
        mm_step_before != ctx->mm.proc_step)
        ctx->changed_flags |= UE_ENGINE_CHANGED_MM;
    if (sm_before != ctx->sm.state ||
        sm_proc_before != ctx->sm.procedure ||
        sm_step_before != ctx->sm.proc_step)
        ctx->changed_flags |= UE_ENGINE_CHANGED_SM;
}

/*
 * Handle RRCSetup: send RRCSetupComplete carrying initial NAS (Registration Request).
 * Transitions RRC state from SETUP_REQUESTED → CONNECTED.
 */
static void engine_handle_rrc_setup(struct ue_context *ctx,
                                    const struct ue_rrc_message *rrc_msg,
                                    uint64_t now_ms)
{
    uint8_t reg_buf[256];
    uint8_t complete_buf[8192];
    int reg_len, complete_len;

    LOG_INF(RRC, "RRCSetup received tx_id=%u", rrc_msg->rrc_transaction_id);

    /*
     * Encode NAS Registration Request to carry inside RRCSetupComplete.
     * This is the correct 5G flow: NAS Registration Request is piggybacked
     * in RRCSetupComplete, not sent before RRCSetupRequest.
     */
    if (ctx->mm.state == UE_MM_REGISTERING && ctx->mm.register_requested) {
        reg_len = ue_nas_encode_registration_request(
            reg_buf, sizeof(reg_buf),
            ctx->cfg.sim.imsi,
            ctx->cfg.network.mcc,
            ctx->cfg.network.mnc,
            ctx->cfg.network.slice_sst,
            engine_reg_type(&ctx->mm),
            ctx->guti_len ? ctx->guti : NULL, ctx->guti_len,
            engine_reg_ngksi(ctx),
            1 /* initial cleartext in RRCSetupComplete */);

        if (reg_len > 0) {
            LOG_DBG(NAS, "Registration Request encoded %d bytes", reg_len);
            LOG_DBG(NAS, "  IEs: EPD SHT Msg ngKSI/regType SUCI(LV-E) SecCap(TLV)%s",
                    ctx->cfg.network.slice_sst ? " Nssai(TLV)" : "");
            {
                int i;
                for (i = 0; i < reg_len && i < 48; i += 8) {
                    int end = i + 8;
                    if (end > reg_len) end = reg_len;
                    LOG_DBG(NAS, "  RegReq[%02d..%02d]:",
                            i, end - 1);
                    {
                        int j;
                        char hex[128] = "";
                        int hpos = 0;
                        for (j = i; j < end; j++)
                            hpos += snprintf(hex + hpos, sizeof(hex) - hpos,
                                             "%s%02x", j > i ? " " : "", reg_buf[j]);
                        LOG_DBG(NAS, "    %s", hex);
                    }
                }
            }
            LOG_DBG(NAS, "  epd=0x%02x sht=0x%02x msg=0x%02x ngKSI/regType=0x%02x",
                    reg_buf[0], reg_buf[1], reg_buf[2], reg_buf[3]);

            complete_len = ue_rrc_encode_setup_complete(
                complete_buf, sizeof(complete_buf),
                rrc_msg->rrc_transaction_id,
                1,  /* selectedPLMN-Identity = 1 (first in SIB1 list) */
                reg_buf, (size_t)reg_len);
            if (complete_len > 0) {
                LOG_DBG(RRC, "RRCSetupComplete encoded %d bytes (nas=%d)", complete_len, reg_len);
                {
                    int i;
                    for (i = 0; i < complete_len && i < 64; i += 8) {
                        int end = i + 8;
                        if (end > complete_len) end = complete_len;
                        {
                            int j;
                            char hex[128] = "";
                            int hpos = 0;
                            for (j = i; j < end; j++)
                                hpos += snprintf(hex + hpos, sizeof(hex) - hpos,
                                                 "%s%02x", j > i ? " " : "", complete_buf[j]);
                            LOG_DBG(RRC, "  RRCComplete[%02d..%02d]: %s", i, end - 1, hex);
                        }
                    }
                }
                LOG_DBG(RRC, "  tx_id=%u plmn_id=%u nas_pdu_len=%zu",
                        rrc_msg->rrc_transaction_id, (unsigned)1, (size_t)reg_len);

                LOG_DBG(NAS, "Registration Request requestedNSSAI=%s",
                        ctx->cfg.network.slice_sst ? "encoded" : "omitted");

                ue_ran_transport_send_nas_pdu(&ctx->ran,
                                             complete_buf,
                                             (size_t)complete_len,
                                             UE_RRC_CHANNEL_UL_DCCH);
            } else {
                LOG_ERR(RRC, "RRCSetupComplete encode failed ret=%d", complete_len);
            }
        } else {
            LOG_ERR(NAS, "Registration Request encode failed ret=%d", reg_len);
        }
    } else {
        /* Should not happen: RRCSetupRequest is only sent when register_requested */
        LOG_WRN(RRC, "RRCSetup received but MM not in REGISTERING state (mm_state=%d reg_req=%d), ignoring",
                ctx->mm.state, ctx->mm.register_requested);
    }

    ctx->rrc_state = UE_RRC_CONNECTED;

    /* Start post-setup core response window */
    ctx->rrc_setup_complete_ms = now_ms;
    ctx->post_setup_pdu_count = 0;
    ctx->waiting_core_response = true;
    LOG_DBG(RRC, "post-setup window opened at %lu ms (delta from request: %lu ms)",
            (unsigned long)now_ms,
            (unsigned long)(now_ms - ctx->rrc_setup_request_ms));
}

/*
 * Initiate RRC connection setup by sending RRCSetupRequest.
 */
static void engine_initiate_rrc_setup(struct ue_context *ctx, uint64_t now_ms)
{
    uint8_t rrc_buf[32];
    int rrc_len;

    /*
     * RRCSetupRequest with random UE identity and cause = mo-Signalling (3).
     * UERANSIM anchor: src/ue/rrc/connection.cpp → sendRrcSetupRequest()
     */
    rrc_len = ue_rrc_encode_setup_request(rrc_buf, sizeof(rrc_buf),
                                          ctx->ran.sti,  /* use STI as random ID */
                                          3);            /* mo-Signalling */
    if (rrc_len > 0) {
        ue_ran_transport_send_nas_pdu(&ctx->ran,
                                     rrc_buf, (size_t)rrc_len,
                                     UE_RRC_CHANNEL_UL_CCCH);
        LOG_INF(RRC, "sending RRCSetupRequest");
        ctx->rrc_state = UE_RRC_SETUP_REQUESTED;
        ctx->rrc_setup_request_ms = now_ms;
    }
}

/*
 * REAL backend tick: drain NAS PDU queue and process each message.
 */
static int engine_real_tick(struct ue_context *ctx, uint64_t now_ms)
{
    uint8_t nas_buf[8192];
    int nas_len;

    /* Radio off: no RAN transport, no MM/SM, no NAS, no user plane */
    if (!ctx->radio_on) {
        engine_reset_rrc_tracking(ctx);
        ue_up_tick(&ctx->up, now_ms);
        return 0;
    }

    LOG_TRC(ENGINE, "engine_real_tick now_ms=%lu", (unsigned long)now_ms);

    /*
     * 1. RAN transport stepping (expire/heartbeat/receive/ack) now runs on the
     * dedicated RLS receive thread (ue_ran_transport_start), so downlink + NAS
     * delivery is no longer gated by this engine tick. Here we only consume the
     * queues it fills (NAS below) and react to its connection state.
     */

    /*
     * 1b. RAN-loss recovery. If the RLS serving cell timed out while we still
     * believe we're registered / have an active PDU session, the gNB has
     * dropped our radio context (we re-appear as a fresh UE with no PDU
     * session -> "Uplink data failure, PDU session not found"). Reset RRC/MM/SM
     * and request a fresh registration so a clean context (and PDU session) is
     * rebuilt once the cell is re-acquired. The condition self-clears after the
     * reset (mm leaves REGISTERED_HOME, sm leaves ACTIVE), so it fires once.
     * Resetting SM also drops connect_activated, which stops the engine from
     * injecting uplink into the dead session.
     */
    if (ctx->ran.state == UE_RAN_TRANSPORT_LOST &&
        (ctx->mm.state == UE_MM_REGISTERED_HOME ||
         ctx->sm.state == UE_SM_ACTIVE)) {
        LOG_WRN(MM, "RAN link lost while registered -> re-registering");
        engine_forget_network_context(ctx);
        ue_sm_on_radio(&ctx->sm, false);   /* drop PDU session locally */
        ue_mm_on_radio(&ctx->mm, false);   /* -> POWERED_OFF */
        ue_mm_on_radio(&ctx->mm, true);    /* -> DEREGISTERED */
        ue_mm_request_register(&ctx->mm);  /* request fresh registration */
    }

    /*
     * 2. MM/SM ticks for timeout handling.
     *
     * In REAL backend, once the initial NAS was sent in RRCSetupComplete,
     * we wait asynchronously for core response (Auth/SMC/RegAccept). During
     * that window, MM retry timeout handling must be paused to avoid
     * premature SEARCHING retry transitions and duplicate registration submit.
     */
    if (!ctx->waiting_core_response)
        ue_mm_tick(&ctx->mm, now_ms);
    ue_sm_tick(&ctx->sm, now_ms, ctx->mm.state == UE_MM_REGISTERED_HOME);

    /*
     * 3. Drain received RRC PDUs → RRC unwrap → NAS decode → inject into MM/SM.
     *
     * The RAN transport NAS queue contains RRC-wrapped PDUs
     * (DLInformationTransfer in UPER). We need to:
     *   a) Decode the RRC wrapper to extract the NAS PDU
     *   b) Handle RRCSetup by sending RRCSetupComplete
     *   c) Decode the NAS PDU and inject into MM/SM
     *
     * The rrc_channel from RLS payload tells us which decode path to try first:
     *   DL_CCCH = 2 (CCCH: RRCSetup)
     *   DL_DCCH = 3 (DCCH: DLInformationTransfer, RRCRelease, etc.)
     */
    {
        uint32_t rrc_channel = 0;
        while ((nas_len = ue_ran_transport_recv_nas_pdu(&ctx->ran,
                                                        nas_buf,
                                                        sizeof(nas_buf),
                                                        &rrc_channel)) > 0) {
            struct ue_rrc_message rrc_msg;
            bool decoded = false;

            LOG_TRC(RRC, "DL PDU %d bytes ch=%u, attempting RRC decode", nas_len, rrc_channel);
            if (nas_len >= 8)
                LOG_TRC(RRC, "DL raw ch=%u: %02x %02x %02x %02x %02x %02x %02x %02x",
                        rrc_channel,
                        nas_buf[0], nas_buf[1], nas_buf[2], nas_buf[3],
                        nas_buf[4], nas_buf[5], nas_buf[6], nas_buf[7]);
            else if (nas_len > 0)
                LOG_TRC(RRC, "DL raw ch=%u: %02x", rrc_channel, nas_buf[0]);

            /* Post-setup PDU counter */
            if (ctx->waiting_core_response)
                ctx->post_setup_pdu_count++;

            /*
             * UERANSIM RRC channel values (src/lib/rrc/rrc.hpp):
             *   DL_CCCH = 2, DL_DCCH = 3
             * Try the channel matching the RLS payload first, then fallback.
             */
            if (rrc_channel == 2 /* DL_CCCH */) {
                /* Try DL-CCCH first (RRCSetup on SRB0) */
                int ret = ue_rrc_decode_dl_ccch(nas_buf, (size_t)nas_len, &rrc_msg);
                LOG_DBG(RRC, "DL-CCCH decode ret=%d", ret);
                if (ret == 0) {
                    LOG_DBG(RRC, "DL-CCCH decoded: type=%d tx_id=%u%s",
                            rrc_msg.type, rrc_msg.rrc_transaction_id,
                            ctx->waiting_core_response ? " [post-setup]" : "");
                    if (rrc_msg.type == UE_RRC_SETUP)
                        engine_handle_rrc_setup(ctx, &rrc_msg, now_ms);
                    decoded = true;
                }
            } else if (rrc_channel == 3 /* DL_DCCH */) {
                /* Try DL-DCCH first (DLInformationTransfer, RRCRelease, etc.) */
                int ret = ue_rrc_decode_dl_dcch(nas_buf, (size_t)nas_len, &rrc_msg);
                LOG_DBG(RRC, "DL-DCCH decode ret=%d", ret);
                if (ret == 0) {
                    LOG_DBG(RRC, "DL-DCCH decoded: type=%d tx_id=%u%s",
                            rrc_msg.type, rrc_msg.rrc_transaction_id,
                            ctx->waiting_core_response ? " [post-setup]" : "");
                    if (rrc_msg.type == UE_RRC_DL_INFO_TRANSFER &&
                        rrc_msg.nas_pdu && rrc_msg.nas_len > 0) {
                        {
                            uint32_t i;
                            char hex[512] = "";
                            int hpos = 0;
                            uint32_t dump = rrc_msg.nas_len < 96 ? rrc_msg.nas_len : 96;
                            for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
                                hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                                                 "%s%02x", i ? " " : "", rrc_msg.nas_pdu[i]);
                            LOG_TRC(NAS, "DLInformationTransfer NAS len=%u hex=%s%s",
                                    rrc_msg.nas_len, hex, rrc_msg.nas_len > dump ? " ..." : "");
                        }
                        LOG_DBG(NAS, "DLInformationTransfer: NAS PDU %d bytes", rrc_msg.nas_len);
                        decode_and_process_nas(ctx,
                                               (uint8_t *)rrc_msg.nas_pdu,
                                               rrc_msg.nas_len);
                    } else if (rrc_msg.type == UE_RRC_SETUP) {
                        engine_handle_rrc_setup(ctx, &rrc_msg, now_ms);
                    }
                    decoded = true;
                }
            }

            /* Fallback: try both decoders if channel unknown or first try failed */
            if (!decoded) {
                int ret_dc, ret_cc;
                ret_dc = ue_rrc_decode_dl_dcch(nas_buf, (size_t)nas_len, &rrc_msg);
                LOG_DBG(RRC, "DL-DCCH fallback ret=%d", ret_dc);
                if (ret_dc == 0) {
                    LOG_DBG(RRC, "DL-DCCH fallback decoded: type=%d%s",
                            rrc_msg.type,
                            ctx->waiting_core_response ? " [post-setup]" : "");
                    if (rrc_msg.type == UE_RRC_DL_INFO_TRANSFER &&
                        rrc_msg.nas_pdu && rrc_msg.nas_len > 0) {
                        LOG_DBG(NAS, "DLInformationTransfer fallback: NAS PDU %d bytes", rrc_msg.nas_len);
                        decode_and_process_nas(ctx,
                                               (uint8_t *)rrc_msg.nas_pdu,
                                               rrc_msg.nas_len);
                    } else if (rrc_msg.type == UE_RRC_SETUP) {
                        engine_handle_rrc_setup(ctx, &rrc_msg, now_ms);
                    }
                    continue;
                }

                /*
                 * In post-setup phase, a DL-DCCH payload (channel=3) should not
                 * be re-qualified as DL-CCCH/RRCSetup via fallback. Avoid false
                 * positives that mask DL-DCCH decode issues.
                 */
                if (ctx->waiting_core_response && rrc_channel == UE_RRC_CHANNEL_DL_DCCH) {
                    LOG_WRN(RRC, "post-setup DL-DCCH decode failed (len=%d), skipping DL-CCCH fallback", nas_len);
                    continue;
                }

                ret_cc = ue_rrc_decode_dl_ccch(nas_buf, (size_t)nas_len, &rrc_msg);
                LOG_DBG(RRC, "DL-CCCH fallback ret=%d", ret_cc);
                if (ret_cc == 0) {
                    LOG_DBG(RRC, "DL-CCCH fallback decoded: type=%d%s",
                            rrc_msg.type,
                            ctx->waiting_core_response ? " [post-setup]" : "");
                    if (rrc_msg.type == UE_RRC_SETUP)
                        engine_handle_rrc_setup(ctx, &rrc_msg, now_ms);
                    continue;
                }

                /* Classification: broadcast vs dedicated */
                if (ctx->waiting_core_response) {
                    LOG_DBG(RRC, "post-setup PDU #%u: ch=%u %d bytes — not RRC (likely broadcast)",
                            ctx->post_setup_pdu_count, rrc_channel, nas_len);
                } else {
                    LOG_DBG(RRC, "DL PDU ch=%u %d bytes: all decoders failed, trying raw NAS",
                            rrc_channel, nas_len);
                }
                decode_and_process_nas(ctx, nas_buf, (size_t)nas_len);
            }
        }
    }

    /* 4. If MM registered and no SM session, auto-connect (like sim path) */
    if (ctx->mm.state == UE_MM_REGISTERED_HOME &&
        ctx->sm.state == UE_SM_INACTIVE &&
        !ctx->sm.connect_requested &&
        !ctx->sm.disconnect_requested) {
        ctx->sm.connect_requested = true;
    }

    /* 5. If MM searching and RAN transport found a cell */
    if (ctx->mm.state == UE_MM_SEARCHING &&
        ue_ran_transport_is_connected(&ctx->ran) &&
        !ctx->waiting_core_response) {
        /*
         * Do NOT submit NAS via the adapter here. Just transition MM to
         * REGISTERING. The NAS Registration Request is sent later by
         * engine_handle_rrc_setup() inside RRCSetupComplete, after the
         * RRCSetup response from the gNB.
         */
        LOG_INF(MM, "cell found, transitioning to REGISTERING");
        ue_mm_transition_to_registering(&ctx->mm);
    }

    /*
     * 5b. RRC connection setup: when MM wants to register and we have
     * a cell but no RRC connection, initiate RRC setup.
     * The MM state machine will submit a Registration Request via
     * the network adapter, but we need the RRC pipe first.
     */
    if (ctx->rrc_state == UE_RRC_IDLE &&
        ue_ran_transport_is_connected(&ctx->ran) &&
        ctx->mm.register_requested) {
        LOG_INF(RRC, "initiating RRC setup (register_requested, transport connected)");
        engine_initiate_rrc_setup(ctx, now_ms);
    }

    /*
     * 5b-bis. Mobility / periodic registration update while already
     * RRC-connected: send the Registration Request directly in an
     * ULInformationTransfer (protected) instead of via RRCSetupComplete.
     * Initial registration (pending_reg_type == INITIAL) keeps using the
     * RRCSetupComplete path above.
     */
    if (ctx->mm.state == UE_MM_REGISTERING &&
        ctx->mm.register_requested &&
        ctx->rrc_state == UE_RRC_CONNECTED &&
        ctx->mm.pending_reg_type != UE_MM_REG_INITIAL &&
        !ctx->waiting_core_response) {
        uint8_t reg_buf[256];
        int reg_len = ue_nas_encode_registration_request(
            reg_buf, sizeof(reg_buf),
            ctx->cfg.sim.imsi, ctx->cfg.network.mcc, ctx->cfg.network.mnc,
            ctx->cfg.network.slice_sst, engine_reg_type(&ctx->mm),
            ctx->guti_len ? ctx->guti : NULL, ctx->guti_len,
            engine_reg_ngksi(ctx),
            0 /* protected mobility/periodic request */);
        if (reg_len > 0) {
            LOG_INF(MM, "sending %s Registration Request (type=%u) via ULInformationTransfer",
                    ctx->mm.pending_reg_trigger == UE_MM_REG_TRIGGER_PERIODIC_UPDATE
                        ? "periodic" : "mobility",
                    engine_reg_type(&ctx->mm));
            engine_send_nas_uplink(ctx, reg_buf, reg_len, false);
            ctx->waiting_core_response = true;
            ctx->rrc_setup_complete_ms = now_ms;
            ctx->post_setup_pdu_count = 0;
        }
    }

    /* 5c. RRC setup timeout: retry after 3 seconds */
    if (ctx->rrc_state == UE_RRC_SETUP_REQUESTED &&
        now_ms - ctx->rrc_setup_request_ms > 3000) {
        LOG_INF(RRC, "RRC setup timeout, resetting to IDLE");
        ctx->rrc_state = UE_RRC_IDLE;  /* allow retry on next tick */
    }

    /* 5e. Post-setup core response window: monitor for core reply */
    if (ctx->waiting_core_response &&
        ctx->rrc_state == UE_RRC_CONNECTED &&
        ctx->mm.state == UE_MM_REGISTERING) {
        uint64_t elapsed = now_ms - ctx->rrc_setup_complete_ms;
        if (elapsed > 15000) {
            LOG_WRN(RRC, "no core response after %lu ms, %u PDUs seen — giving up",
                    (unsigned long)elapsed, ctx->post_setup_pdu_count);
            ctx->waiting_core_response = false;
            ctx->rrc_state = UE_RRC_IDLE;
        } else if (elapsed > 5000 && ctx->post_setup_pdu_count == 0) {
            LOG_WRN(RRC, "no downlink PDU received after %lu ms since RRCSetupComplete",
                    (unsigned long)elapsed);
        }
    }

    /* 5d. Reset RRC state when transport is lost */
    if (!ue_ran_transport_is_connected(&ctx->ran) &&
        ctx->rrc_state != UE_RRC_IDLE) {
        ctx->rrc_state = UE_RRC_IDLE;
    }

    /* 6. Tick user plane: process downlink data, state transitions */
    ue_up_tick(&ctx->up, now_ms);

    return 0;
}

int ue_engine_inject_uplink_ip(struct ue_engine *engine,
                               const uint8_t *ip_packet,
                               size_t len)
{
    if (!engine)
        return -1;

    LOG_TRC(UP, "inject UL IP packet %zu bytes", len);
    return ue_up_send_uplink(&engine->ctx.up, ip_packet, len);
}

int ue_engine_inject_ims_ip(struct ue_engine *engine,
                            const uint8_t *ip_packet,
                            size_t len)
{
    if (!engine || !engine->ctx.ims_pdu_active)
        return -1;
    return ue_up_send_internal_uplink(&engine->ctx.up,
                                      engine->ctx.ims_psi,
                                      ip_packet,
                                      len);
}

int ue_engine_request_ims_pdu(struct ue_engine *engine)
{
    uint8_t nas[512];
    int nas_len;
    uint8_t pti;

    if (!engine)
        return -1;
    if (!engine->ctx.radio_on || engine->ctx.mm.state != UE_MM_REGISTERED_HOME ||
        !engine->ctx.nas_sec.active || engine->ctx.rrc_state != UE_RRC_CONNECTED)
        return -1;
    if (engine->ctx.ims_pdu_active || engine->ctx.ims_pdu_establishing)
        return 0;

    /* Pick a free PDU session id for the internal IMS session: skip the host
     * session and any session already in use, rather than hardcoding psi=2. */
    {
        int free_psi = -1;
        for (int i = 2; i <= 15; i++) {
            if (i == engine->ctx.up.host_psi || engine->ctx.up.sessions[i].used)
                continue;
            free_psi = i;
            break;
        }
        if (free_psi < 0) {
            LOG_WRN(SM, "no free PSI available for IMS PDU session");
            return -1;
        }
        engine->ctx.ims_psi = (uint8_t)free_psi;
    }
    pti = engine->ctx.ims_pti ? (uint8_t)(engine->ctx.ims_pti + 1) : 2;
    if (pti == 0 || pti == 255)
        pti = 2;
    engine->ctx.ims_pti = pti;

    nas_len = ue_nas_encode_pdu_session_est_request(nas, sizeof(nas),
                                                    engine->ctx.ims_psi,
                                                    engine->ctx.ims_pti,
                                                    1 /* IPv4 */,
                                                    1 /* initial */,
                                                    "ims",
                                                    engine->ctx.cfg.network.slice_sst);
    if (nas_len <= 0)
        return -1;

    if (engine_send_nas_uplink(&engine->ctx, nas, nas_len, false) < 0)
        return -1;

    engine->ctx.ims_pdu_requested = true;
    engine->ctx.ims_pdu_establishing = true;
    LOG_INF(SM, "IMS PDU Session Establishment requested psi=%u dnn=ims",
            engine->ctx.ims_psi);
    return 0;
}

int ue_engine_tick(struct ue_engine *engine, uint64_t now_ms)
{
    if (!engine)
        return -1;

    if (engine_real_tick(&engine->ctx, now_ms) < 0)
        return -1;

    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_set_radio(struct ue_engine *engine, bool on)
{
    enum ue_mm_state mm_before;
    enum ue_sm_state sm_before;
    enum ue_mm_procedure mm_proc_before;
    enum ue_sm_procedure sm_proc_before;
    enum ue_mm_proc_step mm_step_before;
    enum ue_sm_proc_step sm_step_before;
    bool had_register_request;
    bool was_radio_on;

    if (!engine)
        return -1;

    mm_before = engine->ctx.mm.state;
    sm_before = engine->ctx.sm.state;
    mm_proc_before = engine->ctx.mm.procedure;
    sm_proc_before = engine->ctx.sm.procedure;
    mm_step_before = engine->ctx.mm.proc_step;
    sm_step_before = engine->ctx.sm.proc_step;

    /* Save registration intent before mm_on_radio may clear it */
    had_register_request = engine->ctx.mm.register_requested;
    was_radio_on = engine->ctx.radio_on;

    engine->ctx.radio_on = on;
    LOG_INF(ENGINE, "radio %s", on ? "ON" : "OFF");

    /* Start/stop RAN transport with radio */
    if (on) {
        if (!was_radio_on)
            engine_forget_network_context(&engine->ctx);
        if (engine->ctx.ran.state == UE_RAN_TRANSPORT_IDLE &&
            engine->ctx.ran.gnb_count > 0) {
            if (ue_ran_transport_start(&engine->ctx.ran) == 0) {
                LOG_INF(RAN, "RAN transport started (socket opened)");
            } else {
                LOG_ERR(RAN, "RAN transport start failed");
            }
        }
    } else if (!on) {
        /*
         * Graceful detach: signal the network BEFORE tearing down the RAN
         * link. A "switch off" Deregistration Request is fire-and-forget (no
         * Deregistration Accept expected), so we send it over the still-open
         * transport and then stop it. This makes the AMF/SMF release the UE
         * context, PDU sessions and IP allocation, so the next radio ON starts
         * from a clean network state instead of colliding with stale context.
         */
        if (engine->ctx.ran.state != UE_RAN_TRANSPORT_IDLE &&
            engine->ctx.nas_sec.active &&
            engine->ctx.guti_len > 0 &&
            (engine->ctx.mm.state == UE_MM_REGISTERED_HOME ||
             engine->ctx.sm.state == UE_SM_ACTIVE)) {
            uint8_t nas[80];
            int nas_len = ue_nas_encode_deregistration_request(
                              nas, sizeof(nas), 1 /* switch off */,
                              engine->ctx.guti, engine->ctx.guti_len,
                              engine->ctx.nas_sec.ngksi);
            if (nas_len > 0) {
                engine_send_nas_uplink(&engine->ctx, nas, nas_len, false);
                LOG_INF(NAS, "sent Deregistration Request (switch off) before radio OFF");
            }
        }

        if (engine->ctx.ran.state != UE_RAN_TRANSPORT_IDLE) {
            ue_ran_transport_stop(&engine->ctx.ran);
            LOG_INF(RAN, "RAN transport stopped (radio OFF)");
        }
        engine_forget_network_context(&engine->ctx);
    }

    ue_mm_on_radio(&engine->ctx.mm, on);
    ue_sm_on_radio(&engine->ctx.sm, on);

    /* Radio ON starts a fresh initial registration after the forced cleanup. */
    if (on && engine->ctx.mm.state == UE_MM_DEREGISTERED) {
        LOG_INF(MM, "%s registration after radio ON",
                had_register_request ? "re-invoking pending" : "starting fresh");
        ue_mm_request_register(&engine->ctx.mm);
    }

    if (mm_before != engine->ctx.mm.state ||
        mm_proc_before != engine->ctx.mm.procedure ||
        mm_step_before != engine->ctx.mm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_MM;
    if (sm_before != engine->ctx.sm.state ||
        sm_proc_before != engine->ctx.sm.procedure ||
        sm_step_before != engine->ctx.sm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_SM;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_request_register(struct ue_engine *engine)
{
    enum ue_mm_state before;
    enum ue_mm_procedure proc_before;
    enum ue_mm_proc_step step_before;

    if (!engine)
        return -1;

    before = engine->ctx.mm.state;
    proc_before = engine->ctx.mm.procedure;
    step_before = engine->ctx.mm.proc_step;
    ue_mm_request_register(&engine->ctx.mm);
    if (before != engine->ctx.mm.state ||
        proc_before != engine->ctx.mm.procedure ||
        step_before != engine->ctx.mm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_MM;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_request_periodic_update(struct ue_engine *engine)
{
    enum ue_mm_state before;
    enum ue_mm_procedure proc_before;
    enum ue_mm_proc_step step_before;

    if (!engine)
        return -1;

    before = engine->ctx.mm.state;
    proc_before = engine->ctx.mm.procedure;
    step_before = engine->ctx.mm.proc_step;
    ue_mm_request_periodic_update(&engine->ctx.mm);
    if (before != engine->ctx.mm.state ||
        proc_before != engine->ctx.mm.procedure ||
        step_before != engine->ctx.mm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_MM;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_request_mobility_update(struct ue_engine *engine)
{
    enum ue_mm_state before;
    enum ue_mm_procedure proc_before;
    enum ue_mm_proc_step step_before;

    if (!engine)
        return -1;

    before = engine->ctx.mm.state;
    proc_before = engine->ctx.mm.procedure;
    step_before = engine->ctx.mm.proc_step;
    ue_mm_request_mobility_update(&engine->ctx.mm);
    if (before != engine->ctx.mm.state ||
        proc_before != engine->ctx.mm.procedure ||
        step_before != engine->ctx.mm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_MM;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_request_connect(struct ue_engine *engine, const char *dnn)
{
    enum ue_sm_state before;
    enum ue_sm_procedure proc_before;
    enum ue_sm_proc_step step_before;

    if (!engine)
        return -1;

    before = engine->ctx.sm.state;
    proc_before = engine->ctx.sm.procedure;
    step_before = engine->ctx.sm.proc_step;
    ue_sm_request_connect(&engine->ctx.sm, dnn);
    if (before != engine->ctx.sm.state ||
        proc_before != engine->ctx.sm.procedure ||
        step_before != engine->ctx.sm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_SM;
    engine->ctx.changed_flags |= UE_ENGINE_CHANGED_DNN;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

int ue_engine_request_disconnect(struct ue_engine *engine)
{
    enum ue_sm_state before;
    enum ue_sm_procedure proc_before;
    enum ue_sm_proc_step step_before;

    if (!engine)
        return -1;

    before = engine->ctx.sm.state;
    proc_before = engine->ctx.sm.procedure;
    step_before = engine->ctx.sm.proc_step;
    ue_sm_request_disconnect(&engine->ctx.sm);
    if (before != engine->ctx.sm.state ||
        proc_before != engine->ctx.sm.procedure ||
        step_before != engine->ctx.sm.proc_step)
        engine->ctx.changed_flags |= UE_ENGINE_CHANGED_SM;
    ue_context_refresh_snapshot(&engine->ctx);
    return 0;
}

const struct ue_engine_snapshot *ue_engine_snapshot(const struct ue_engine *engine)
{
    if (!engine)
        return NULL;
    return &engine->ctx.snapshot;
}

uint32_t ue_engine_take_changed(struct ue_engine *engine)
{
    uint32_t changed;

    if (!engine)
        return UE_ENGINE_CHANGED_NONE;

    changed = engine->ctx.changed_flags;
    engine->ctx.changed_flags = UE_ENGINE_CHANGED_NONE;
    return changed;
}
