#include "state_bridge.h"

#include "../common/log.h"
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../modem_state/modem_state.h"
#include "../ims_service/ims_service.h"
#include "../ue_engine/ue_engine.h"
#include "../ue_engine/ue_up.h"
#include "../runtime/ue_instance_config.h"
#include "../runtime/ue_timers.h"

struct state_bridge {
    struct ue_engine engine;
    struct ims_service *ims;
    struct apn_context_manager apn_contexts;
    struct ue_engine_snapshot prev;
    enum mbim_bridge_indication ind_queue[16];
    int ind_head;
    int ind_tail;

    /* Incoming SMS (from IMS worker thread) queued for the MBIM frontend. */
    struct {
        uint8_t data[512];
        size_t len;
    } sms_queue[16];
    int sms_head;
    int sms_tail;
    pthread_mutex_t sms_lock;
};

static struct state_bridge *g_default_bridge;

int state_bridge_init_with_config(struct state_bridge **out_bridge,
                                  const struct ue_instance_config *cfg);

static int ind_queue_empty(struct state_bridge *b)
{
    return b->ind_head == b->ind_tail;
}

static int ind_queue_full(struct state_bridge *b)
{
    return ((b->ind_tail + 1) % 16) == b->ind_head;
}

static int ind_queue_count(struct state_bridge *b)
{
    if (!b)
        return 0;
    return (b->ind_tail - b->ind_head + 16) % 16;
}

static void ind_enqueue(struct state_bridge *b, enum mbim_bridge_indication ind)
{
    if (!b || ind == MBIM_BRIDGE_IND_NONE)
        return;

    if (ind_queue_full(b)) {
        LOG_WRN(SBRG, "indication queue full, dropping type=%d count=%d head=%d tail=%d",
                ind, ind_queue_count(b), b->ind_head, b->ind_tail);
        return;
    }

    b->ind_queue[b->ind_tail] = ind;
    b->ind_tail = (b->ind_tail + 1) % 16;
    LOG_DBG(SBRG, "indication queued type=%d count=%d head=%d tail=%d",
            ind, ind_queue_count(b), b->ind_head, b->ind_tail);
}

static enum mbim_bridge_indication ind_dequeue(struct state_bridge *b)
{
    enum mbim_bridge_indication ind;

    if (!b || ind_queue_empty(b))
        return MBIM_BRIDGE_IND_NONE;

    ind = b->ind_queue[b->ind_head];
    b->ind_head = (b->ind_head + 1) % 16;
    LOG_DBG(SBRG, "indication dequeued type=%d count=%d head=%d tail=%d",
            ind, ind_queue_count(b), b->ind_head, b->ind_tail);
    return ind;
}

static void ind_drop_first(struct state_bridge *b, enum mbim_bridge_indication target)
{
    int idx;
    int cur;

    if (!b || ind_queue_empty(b))
        return;

    idx = b->ind_head;
    while (idx != b->ind_tail) {
        if (b->ind_queue[idx] == target)
            break;
        idx = (idx + 1) % 16;
    }

    if (idx == b->ind_tail) {
        LOG_DBG(SBRG, "ind_drop_first not_found type=%d count=%d head=%d tail=%d",
                target, ind_queue_count(b), b->ind_head, b->ind_tail);
        return;
    }

    cur = idx;
    while (cur != b->ind_tail) {
        int next = (cur + 1) % 16;
        if (next == b->ind_tail)
            break;
        b->ind_queue[cur] = b->ind_queue[next];
        cur = next;
    }

    b->ind_tail = (b->ind_tail - 1 + 16) % 16;
    LOG_WRN(SBRG, "ind_drop_first removed type=%d count=%d head=%d tail=%d",
            target, ind_queue_count(b), b->ind_head, b->ind_tail);
}

/* ---- SMS over IMS bridging ---- */

static bool sms_queue_empty(struct state_bridge *b)
{
    return !b || b->sms_head == b->sms_tail;
}

static bool sms_queue_full(struct state_bridge *b)
{
    return b && ((b->sms_tail + 1) % 16) == b->sms_head;
}

/* Incoming SMS PDU from the IMS worker thread -> queue for the MBIM frontend. */
static int bridge_sms_downlink_cb(const uint8_t *pdu, size_t len, void *user_data)
{
    struct state_bridge *b = user_data;

    if (!b || !pdu || len == 0)
        return -1;
    if (len > sizeof(b->sms_queue[0].data)) {
        LOG_WRN(SBRG, "incoming SMS too large len=%zu", len);
        return -1;
    }

    pthread_mutex_lock(&b->sms_lock);
    if (sms_queue_full(b)) {
        pthread_mutex_unlock(&b->sms_lock);
        LOG_WRN(SBRG, "incoming SMS queue full, dropping");
        return -1;
    }

    memcpy(b->sms_queue[b->sms_tail].data, pdu, len);
    b->sms_queue[b->sms_tail].len = len;
    b->sms_tail = (b->sms_tail + 1) % 16;
    pthread_mutex_unlock(&b->sms_lock);
    LOG_DBG(SBRG, "incoming SMS queued len=%zu", len);
    return 0;
}

/* IMS worker thread -> uplink IP packet injected on the internal IMS PSI. */
static int bridge_ims_ip_uplink_cb(const uint8_t *packet,
                                   size_t packet_len,
                                   void *user_data)
{
    struct state_bridge *b = user_data;

    if (!b)
        return -1;
    return ue_engine_inject_ims_ip(&b->engine, packet, packet_len);
}

/* RLS rx thread -> downlink IP packet for the internal IMS session. */
static int bridge_ims_ip_downlink_cb(int psi, const uint8_t *data,
                                     size_t len, void *user_data)
{
    struct state_bridge *b = user_data;

    if (!b)
        return -1;
    return ims_service_receive_ip(b->ims, psi, data, len);
}

int state_bridge_init(struct state_bridge **out_bridge)
{
    struct ue_instance_config cfg;

    if (ue_instance_config_set_defaults(&cfg) < 0)
        return -1;
    if (ue_instance_config_finalize(&cfg, 1, false) < 0)
        return -1;

    return state_bridge_init_with_config(out_bridge, &cfg);
}

int state_bridge_init_with_config(struct state_bridge **out_bridge,
                                  const struct ue_instance_config *cfg)
{
    struct state_bridge *bridge = calloc(1, sizeof(*bridge));
    if (!bridge)
        return -1;

    pthread_mutex_init(&bridge->sms_lock, NULL);
    if (ue_engine_init(&bridge->engine, cfg, 1) < 0)
        goto fail;

    apn_context_manager_init(&bridge->apn_contexts, cfg->ims.enabled);
    apn_context_upsert(&bridge->apn_contexts,
                       cfg->network.dnn,
                       APN_CONTEXT_IP_TYPE_IPV4,
                       APN_CONTEXT_SOURCE_INTERNAL,
                       NULL);
    /*
     * Provision the internal "ims" APN so an IMS PDU session is requested
     * automatically after registration (state_bridge_poll -> has_ims_context).
     * Classified as IMS_INTERNAL only when cfg->ims.enabled.
     */
    if (cfg->ims.enabled)
        apn_context_upsert(&bridge->apn_contexts, "ims",
                           APN_CONTEXT_IP_TYPE_IPV4,
                           APN_CONTEXT_SOURCE_INTERNAL,
                           NULL);

    if (ims_service_init(&bridge->ims, cfg) < 0)
        goto fail;
    ims_service_set_tx_callback(bridge->ims, bridge_ims_ip_uplink_cb, bridge);
    ims_service_set_sms_downlink_callback(bridge->ims, bridge_sms_downlink_cb, bridge);
    /* IMS-only: downlink IMS IP packets routed from the RLS rx thread. */
    ue_up_set_internal_downlink_callback(&bridge->engine.ctx.up,
                                         bridge_ims_ip_downlink_cb,
                                         bridge);

    if (ue_engine_start(&bridge->engine) < 0)
        goto fail;
    bridge->prev = *ue_engine_snapshot(&bridge->engine);

    *out_bridge = bridge;
    return 0;

fail:
    /* Tear the engine down first (joins the RLS threads) so no internal-session
     * downlink callback can still reach the IMS service being freed below. */
    ue_engine_deinit(&bridge->engine);
    ims_service_destroy(bridge->ims);
    pthread_mutex_destroy(&bridge->sms_lock);
    free(bridge);
    return -1;
}

void state_bridge_destroy(struct state_bridge *bridge)
{
    if (bridge) {
        /*
         * Order matters: ue_engine_stop()+deinit() stop and join the RLS RX/HB
         * threads, after which bridge_ims_ip_downlink_cb() -> ims_service_receive_ip()
         * can no longer run. Only then is it safe to destroy the IMS service.
         */
        ue_engine_stop(&bridge->engine);
        ue_engine_deinit(&bridge->engine);
        ims_service_destroy(bridge->ims);
        pthread_mutex_destroy(&bridge->sms_lock);
    }
    free(bridge);
}

int state_bridge_init_default(void)
{
    struct ue_instance_config cfg;

    if (ue_instance_config_set_defaults(&cfg) < 0)
        return -1;
    if (ue_instance_config_finalize(&cfg, 1, false) < 0)
        return -1;

    return state_bridge_init_default_with_config(&cfg);
}

int state_bridge_init_default_with_config(const struct ue_instance_config *cfg)
{
    if (g_default_bridge)
        return 0;
    return state_bridge_init_with_config(&g_default_bridge, cfg);
}

void state_bridge_shutdown_default(void)
{
    state_bridge_destroy(g_default_bridge);
    g_default_bridge = NULL;
}

int state_bridge_poll(void)
{
    const struct ue_engine_snapshot *snap;
    uint64_t now_ms;

    if (!g_default_bridge)
        return -ENODEV;

    now_ms = ue_timers_now_ms();
    if (ue_engine_tick(&g_default_bridge->engine, now_ms) < 0)
        return -1;

    snap = ue_engine_snapshot(&g_default_bridge->engine);
    if (!snap)
        return -1;

    g_modem_state.radio_hw_on = true;
    g_modem_state.radio_sw_on = snap->radio_on;
    g_modem_state.sim_ready = snap->sim_ready;
    g_modem_state.registered_home = (snap->mm_state == UE_MM_REGISTERED_HOME);
    g_modem_state.packet_attached = (snap->sm_state == UE_SM_ACTIVE);
    g_modem_state.serving_connected = g_modem_state.registered_home;
    g_modem_state.connect_activated = (snap->sm_state == UE_SM_ACTIVE);
    g_modem_state.connect_session_id = snap->session_id;

    snprintf(g_modem_state.identity.imsi, sizeof(g_modem_state.identity.imsi), "%s", snap->imsi);
    snprintf(g_modem_state.identity.iccid, sizeof(g_modem_state.identity.iccid), "%s", snap->iccid);
    snprintf(g_modem_state.identity.imei, sizeof(g_modem_state.identity.imei), "%s", snap->imei);
    snprintf(g_modem_state.identity.manufacturer, sizeof(g_modem_state.identity.manufacturer), "%s", snap->manufacturer);
    snprintf(g_modem_state.identity.model, sizeof(g_modem_state.identity.model), "%s", snap->model);
    snprintf(g_modem_state.identity.firmware, sizeof(g_modem_state.identity.firmware), "%s", snap->firmware);
    snprintf(g_modem_state.identity.serial, sizeof(g_modem_state.identity.serial), "%s", snap->serial);
    snprintf(g_modem_state.oper.plmn, sizeof(g_modem_state.oper.plmn), "%s", snap->plmn);
    snprintf(g_modem_state.oper.name, sizeof(g_modem_state.oper.name), "%s", snap->operator_name);
    snprintf(g_modem_state.apn, sizeof(g_modem_state.apn), "%s", snap->active_dnn);

    g_modem_state.ip.ipv4_addr[0] = snap->ip.ipv4_addr[0];
    g_modem_state.ip.ipv4_addr[1] = snap->ip.ipv4_addr[1];
    g_modem_state.ip.ipv4_addr[2] = snap->ip.ipv4_addr[2];
    g_modem_state.ip.ipv4_addr[3] = snap->ip.ipv4_addr[3];
    g_modem_state.ip.ipv4_gw[0] = snap->ip.ipv4_gw[0];
    g_modem_state.ip.ipv4_gw[1] = snap->ip.ipv4_gw[1];
    g_modem_state.ip.ipv4_gw[2] = snap->ip.ipv4_gw[2];
    g_modem_state.ip.ipv4_gw[3] = snap->ip.ipv4_gw[3];
    g_modem_state.ip.ipv4_dns1[0] = snap->ip.dns1[0];
    g_modem_state.ip.ipv4_dns1[1] = snap->ip.dns1[1];
    g_modem_state.ip.ipv4_dns1[2] = snap->ip.dns1[2];
    g_modem_state.ip.ipv4_dns1[3] = snap->ip.dns1[3];
    g_modem_state.ip.mtu = snap->ip.mtu;

    LOG_TRC(SBRG, "poll mm=%d sm=%d radio=%s registered=%s packet=%s",
            snap->mm_state, snap->sm_state,
            snap->radio_on ? "on" : "off",
            g_modem_state.registered_home ? "yes" : "no",
            g_modem_state.packet_attached ? "yes" : "no");

    /*
     * SMS over IMS: once registered, request the internal IMS PDU session, and
     * keep the IMS service informed of its PDU/P-CSCF state so its worker can
     * (re)run SIP REGISTER. request_ims_pdu is internally idempotent and guards
     * on radio/registration/RRC/nas-security preconditions.
     */
    if (snap->mm_state == UE_MM_REGISTERED_HOME &&
        state_bridge_has_ims_context() &&
        !g_default_bridge->engine.ctx.ims_pdu_requested) {
        (void)ue_engine_request_ims_pdu(&g_default_bridge->engine);
    }
    ims_service_set_pdu_active(g_default_bridge->ims,
                               g_default_bridge->engine.ctx.ims_pdu_active,
                               g_default_bridge->engine.ctx.ims_ip.ipv4_addr,
                               g_default_bridge->engine.ctx.ims_has_pcscf,
                               g_default_bridge->engine.ctx.ims_pcscf_ipv4);

    if (g_default_bridge->prev.mm_state != snap->mm_state ||
        g_default_bridge->prev.sm_state != snap->sm_state) {
        LOG_INF(SBRG, "state change mm %d->%d sm %d->%d",
                g_default_bridge->prev.mm_state, snap->mm_state,
                g_default_bridge->prev.sm_state, snap->sm_state);
    }

    if (g_default_bridge->prev.mm_state != UE_MM_REGISTERED_HOME &&
        snap->mm_state == UE_MM_REGISTERED_HOME) {
        ind_enqueue(g_default_bridge, MBIM_BRIDGE_IND_REGISTER_HOME);
        LOG_DBG(SBRG, "indication enqueued type=%d", MBIM_BRIDGE_IND_REGISTER_HOME);
    }

    if (g_default_bridge->prev.mm_state == UE_MM_REGISTERED_HOME &&
        snap->mm_state != UE_MM_REGISTERED_HOME) {
        ind_enqueue(g_default_bridge, MBIM_BRIDGE_IND_REGISTER_DEREGISTERED);
        LOG_DBG(SBRG, "indication enqueued type=%d", MBIM_BRIDGE_IND_REGISTER_DEREGISTERED);
    }

    if (g_default_bridge->prev.sm_state != UE_SM_ESTABLISHING &&
        snap->sm_state == UE_SM_ESTABLISHING) {
        ind_enqueue(g_default_bridge, MBIM_BRIDGE_IND_PACKET_ATTACHING);
        LOG_DBG(SBRG, "indication enqueued type=%d (SM %d->%d)",
                MBIM_BRIDGE_IND_PACKET_ATTACHING,
                g_default_bridge->prev.sm_state, snap->sm_state);
    }

    if (g_default_bridge->prev.sm_state != UE_SM_ACTIVE && snap->sm_state == UE_SM_ACTIVE) {
        ind_drop_first(g_default_bridge, MBIM_BRIDGE_IND_PACKET_ATTACHING);
        ind_enqueue(g_default_bridge, MBIM_BRIDGE_IND_PACKET_ATTACHED);
        LOG_DBG(SBRG, "packet attached bridge indication queued type=%d", MBIM_BRIDGE_IND_PACKET_ATTACHED);
        LOG_DBG(SBRG, "indication enqueued type=%d (SM %d->%d)",
                MBIM_BRIDGE_IND_PACKET_ATTACHED,
                g_default_bridge->prev.sm_state, snap->sm_state);
    }

    if (g_default_bridge->prev.sm_state == UE_SM_ACTIVE && snap->sm_state != UE_SM_ACTIVE) {
        ind_drop_first(g_default_bridge, MBIM_BRIDGE_IND_PACKET_ATTACHING);
        ind_enqueue(g_default_bridge, MBIM_BRIDGE_IND_PACKET_DETACHED);
        LOG_DBG(SBRG, "packet detached bridge indication queued type=%d", MBIM_BRIDGE_IND_PACKET_DETACHED);
    }

    g_default_bridge->prev = *snap;
    return 0;
}

int state_bridge_set_radio(bool on)
{
    if (!g_default_bridge)
        return -ENODEV;
    LOG_INF(SBRG, "set_radio %s", on ? "ON" : "OFF");
    return ue_engine_set_radio(&g_default_bridge->engine, on);
}

int state_bridge_request_register(void)
{
    if (!g_default_bridge)
        return -ENODEV;
    LOG_INF(SBRG, "request_register");
    ind_enqueue(g_default_bridge, MBIM_BRIDGE_IND_REGISTER_SEARCHING);
    LOG_DBG(SBRG, "indication enqueued type=%d", MBIM_BRIDGE_IND_REGISTER_SEARCHING);
    return ue_engine_request_register(&g_default_bridge->engine);
}

int state_bridge_request_connect(const char *apn)
{
    const struct ue_engine_snapshot *snap;

    if (!g_default_bridge)
        return -ENODEV;
    LOG_INF(SBRG, "request_connect apn=%s", apn);
    snap = ue_engine_snapshot(&g_default_bridge->engine);
    if (snap && !snap->radio_on) {
        LOG_INF(SBRG, "request_connect while radio OFF -> radio ON + fresh registration");
        ue_engine_set_radio(&g_default_bridge->engine, true);
        ue_engine_request_register(&g_default_bridge->engine);
    }
    return ue_engine_request_connect(&g_default_bridge->engine, apn);
}

int state_bridge_request_disconnect(void)
{
    if (!g_default_bridge)
        return -ENODEV;
    LOG_INF(SBRG, "request_disconnect -> full UE context reset");
    (void)ue_engine_request_disconnect(&g_default_bridge->engine);
    return ue_engine_set_radio(&g_default_bridge->engine, false);
}

enum mbim_bridge_indication state_bridge_next_indication(void)
{
    enum mbim_bridge_indication ind = ind_dequeue(g_default_bridge);
    LOG_DBG(SBRG, "state_bridge_next_indication -> %d", ind);
    return ind;
}

bool state_bridge_has_pending_indication(void)
{
    if (!g_default_bridge)
        return false;
    return !ind_queue_empty(g_default_bridge);
}

struct ue_engine *state_bridge_default_engine(void)
{
    if (!g_default_bridge)
        return NULL;
    return &g_default_bridge->engine;
}

/* ---- SMS over IMS (IMS-only) ---- */

int state_bridge_send_sms_ims(const uint8_t *sms_pdu, size_t sms_pdu_len,
                              uint32_t *reference)
{
    if (!g_default_bridge)
        return -ENODEV;
    LOG_INF(SBRG, "send_sms_ims len=%zu", sms_pdu_len);
    return ims_service_submit_sms(g_default_bridge->ims, sms_pdu, sms_pdu_len,
                                  reference);
}

int state_bridge_upsert_apn_context(const char *apn,
                                    enum apn_context_ip_type ip_type,
                                    enum apn_context_source source,
                                    uint32_t *out_id)
{
    if (!g_default_bridge)
        return -ENODEV;
    return apn_context_upsert(&g_default_bridge->apn_contexts, apn, ip_type,
                              source, out_id);
}

bool state_bridge_has_ims_context(void)
{
    return g_default_bridge &&
           apn_context_get_ims(&g_default_bridge->apn_contexts) != NULL;
}

bool state_bridge_has_pending_sms(void)
{
    bool pending;

    if (!g_default_bridge)
        return false;
    pthread_mutex_lock(&g_default_bridge->sms_lock);
    pending = !sms_queue_empty(g_default_bridge);
    pthread_mutex_unlock(&g_default_bridge->sms_lock);
    return pending;
}

bool state_bridge_pop_sms(uint8_t *out, size_t out_cap, size_t *out_len)
{
    struct state_bridge *b = g_default_bridge;
    size_t len;

    if (out_len)
        *out_len = 0;
    if (!b || !out || !out_len)
        return false;

    pthread_mutex_lock(&b->sms_lock);
    if (sms_queue_empty(b)) {
        pthread_mutex_unlock(&b->sms_lock);
        return false;
    }

    len = b->sms_queue[b->sms_head].len;
    if (len > out_cap) {
        pthread_mutex_unlock(&b->sms_lock);
        return false;
    }
    memcpy(out, b->sms_queue[b->sms_head].data, len);
    b->sms_head = (b->sms_head + 1) % 16;
    pthread_mutex_unlock(&b->sms_lock);
    *out_len = len;
    LOG_DBG(SBRG, "incoming SMS dequeued len=%zu", len);
    return true;
}

bool state_bridge_ims_enabled(void)
{
    return g_default_bridge && ims_service_enabled(g_default_bridge->ims);
}

bool state_bridge_sms_enabled(void)
{
    return g_default_bridge && g_default_bridge->engine.ctx.cfg.sms.enabled;
}

enum ue_sms_transport_mode state_bridge_sms_transport(void)
{
    if (!g_default_bridge)
        return UE_SMS_TRANSPORT_AUTO;
    return g_default_bridge->engine.ctx.cfg.sms.transport;
}

bool state_bridge_ims_registered(void)
{
    return g_default_bridge && ims_service_registered(g_default_bridge->ims);
}

/*
 * Downlink callback adapter: matches ue_up_downlink_cb signature,
 * forwards to the registered state_bridge_dl_cb.
 */
static state_bridge_dl_cb g_dl_callback = NULL;
static void *g_dl_user_data = NULL;

static int bridge_dl_adapter(int psi, const uint8_t *data,
                             size_t len, void *user_data)
{
    (void)user_data;
    if (g_dl_callback)
        return g_dl_callback(psi, data, len, g_dl_user_data);
    return -1;
}

int state_bridge_set_downlink_callback(state_bridge_dl_cb cb, void *user_data)
{
    if (!g_default_bridge)
        return -1;

    g_dl_callback = cb;
    g_dl_user_data = user_data;

    ue_up_set_downlink_callback(&g_default_bridge->engine.ctx.up,
                                bridge_dl_adapter, NULL);
    return 0;
}
