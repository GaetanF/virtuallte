/*
 * ue_up.c - UE User Plane data path implementation.
 *
 * UERANSIM anchor:
 *   - src/ue/tun/task.cpp       : TUN read/write (we replace with MBIM USB)
 *   - src/ue/app/task.cpp       : session establishment → TUN creation
 *   - src/ue/nas/sm/transport.cpp : SM↔RLS data routing
 *
 * Data flow (target):
 *   Uplink:  MBIM USB → ue_up_send_uplink() → ue_ran_transport_send_data_pdu()
 *   Downlink: ue_ran_transport_recv_data_pdu() → ue_up_process_downlink()
 *             → dl_callback → MBIM USB
 */

#include "ue_up.h"
#include "ue_ran_transport.h"

#include <string.h>

#include "../common/log.h"

void ue_up_init(struct ue_up_ctx *up)
{
    if (!up)
        return;
    memset(up, 0, sizeof(*up));
    up->state = UE_UP_IDLE;
    up->has_session = false;
    up->host_psi = 0;
    up->transport = NULL;
    up->dl_callback = NULL;
    up->dl_callback_data = NULL;
    up->internal_dl_callback = NULL;
    up->internal_dl_callback_data = NULL;
}

void ue_up_set_transport(struct ue_up_ctx *up,
                         struct ue_ran_transport_ctx *transport)
{
    if (!up)
        return;
    up->transport = transport;
}

void ue_up_set_downlink_callback(struct ue_up_ctx *up,
                                 ue_up_downlink_cb cb,
                                 void *user_data)
{
    if (!up)
        return;
    up->dl_callback = cb;
    up->dl_callback_data = user_data;
}

void ue_up_set_internal_downlink_callback(struct ue_up_ctx *up,
                                          ue_up_internal_downlink_cb cb,
                                          void *user_data)
{
    if (!up)
        return;
    up->internal_dl_callback = cb;
    up->internal_dl_callback_data = user_data;
}

int ue_up_bind_session(struct ue_up_ctx *up,
                       int psi,
                       const char *dnn,
                       const char *pdu_type,
                       const struct ue_engine_runtime_ip *ip)
{
    return ue_up_bind_session_ex(up, psi, dnn, pdu_type, ip, true);
}

int ue_up_bind_session_ex(struct ue_up_ctx *up,
                          int psi,
                          const char *dnn,
                          const char *pdu_type,
                          const struct ue_engine_runtime_ip *ip,
                          bool host_visible)
{
    struct ue_up_session *s;

    if (!up || psi < 1 || psi > 15)
        return -1;

    s = &up->sessions[psi];
    memset(s, 0, sizeof(*s));
    s->used = true;
    s->host_visible = host_visible;
    s->psi = psi;

    if (dnn) {
        strncpy(s->dnn, dnn, sizeof(s->dnn) - 1);
        s->dnn[sizeof(s->dnn) - 1] = '\0';
    }
    if (pdu_type) {
        strncpy(s->pdu_type, pdu_type, sizeof(s->pdu_type) - 1);
        s->pdu_type[sizeof(s->pdu_type) - 1] = '\0';
    }
    if (ip) {
        memcpy(s->ipv4_addr, ip->ipv4_addr, 4);
        memcpy(s->ipv4_gw, ip->ipv4_gw, 4);
        memcpy(s->dns1, ip->dns1, 4);
        memcpy(s->dns2, ip->dns2, 4);
        s->mtu = ip->mtu;
    }

    if (host_visible) {
        up->session = *s;
        up->has_session = true;
        up->host_psi = psi;
    }

    LOG_INF(UP, "bind session psi=%d dnn=%s host_visible=%s",
            psi, dnn ? dnn : "(null)", host_visible ? "yes" : "no");

    /*
     * Transition to ACTIVE if transport is connected.
     * Otherwise BINDING until transport comes up.
     *
     * UERANSIM anchor: UeAppTask::handleStatusUpdate(SESSION_ESTABLISHMENT)
     *   creates TUN and starts TunTask immediately.
     * We go through BINDING→ACTIVE since transport may not be ready.
     */
    if (up->has_session && up->transport && ue_ran_transport_is_connected(up->transport))
        up->state = UE_UP_ACTIVE;
    else if (up->has_session)
        up->state = UE_UP_BINDING;

    return 0;
}

void ue_up_unbind_session(struct ue_up_ctx *up)
{
    if (!up)
        return;

    LOG_INF(UP, "unbind session");
    if (up->host_psi >= 1 && up->host_psi <= 15)
        memset(&up->sessions[up->host_psi], 0, sizeof(up->sessions[up->host_psi]));
    memset(&up->session, 0, sizeof(up->session));
    up->has_session = false;
    up->host_psi = 0;
    up->state = UE_UP_IDLE;
}

void ue_up_unbind_session_psi(struct ue_up_ctx *up, int psi)
{
    if (!up || psi < 1 || psi > 15)
        return;
    if (!up->sessions[psi].used)
        return;

    LOG_INF(UP, "unbind session psi=%d", psi);
    memset(&up->sessions[psi], 0, sizeof(up->sessions[psi]));
    if (up->host_psi == psi) {
        memset(&up->session, 0, sizeof(up->session));
        up->has_session = false;
        up->host_psi = 0;
        up->state = UE_UP_IDLE;
    }
}

int ue_up_send_uplink(struct ue_up_ctx *up,
                       const uint8_t *ip_packet, size_t len)
{
    int rc;

    if (!up || !ip_packet || len == 0)
        return -1;

    if (up->state != UE_UP_ACTIVE || !up->has_session) {
        LOG_WRN(UP, "UL drop %zu bytes (state=%d)", len, up->state);
        up->ul_drops++;
        return -1;
    }

    if (!up->transport) {
        LOG_WRN(UP, "UL drop %zu bytes (state=%d)", len, up->state);
        up->ul_drops++;
        return -1;
    }

    /*
     * Send through RAN transport as a DATA PDU.
     *
     * UERANSIM path: TunTask → NmUeTunToApp(DATA_PDU_DELIVERY)
     *   → AppTask → NmUeAppToNas(UPLINK_DATA)
     *   → NasTask/SM → NmUeNasToRls(DATA_PDU_DELIVERY)
     *   → RlsTask → RLS PDU_TRANSMISSION(DATA, psi)
     *
     * We shortcut: ue_up → ue_ran_transport_send_data_pdu(psi, packet)
     */
    rc = ue_ran_transport_send_data_pdu(up->transport,
                                        up->host_psi,
                                        ip_packet, len);
    if (rc < 0) {
        up->ul_drops++;
        return -1;
    }

    LOG_TRC(UP, "UL send %zu bytes psi=%d state=%d", len, up->host_psi, up->state);
    up->ul_packets++;
    up->ul_bytes += len;
    return 0;
}

int ue_up_send_internal_uplink(struct ue_up_ctx *up,
                               int psi,
                               const uint8_t *ip_packet, size_t len)
{
    int rc;

    if (!up || !ip_packet || len == 0 || psi < 1 || psi > 15)
        return -1;

    if (!up->transport || !up->sessions[psi].used || up->sessions[psi].host_visible) {
        LOG_WRN(UP, "internal UL drop %zu bytes psi=%d", len, psi);
        up->ul_drops++;
        return -1;
    }

    rc = ue_ran_transport_send_data_pdu(up->transport, psi, ip_packet, len);
    if (rc < 0) {
        up->ul_drops++;
        return -1;
    }

    LOG_TRC(UP, "internal UL send %zu bytes psi=%d", len, psi);
    up->ul_packets++;
    up->ul_bytes += len;
    return 0;
}

int ue_up_process_downlink(struct ue_up_ctx *up)
{
    uint8_t pkt_buf[16384];
    int psi = 0;
    int pkt_len;
    int delivered = 0;

    if (!up || !up->transport)
        return -1;

    /*
     * Drain whenever the RAN transport is connected and at least one session is
     * bound — host OR internal. up->state/has_session track only the host
     * session, so gating on them would starve an internal-only session (e.g. the
     * IMS PDU session) of its downlink SIP/SMS packets. Per-PSI routing below
     * dispatches host vs internal correctly.
     */
    {
        bool any_session = up->has_session;
        for (int i = 1; i <= 15 && !any_session; i++)
            if (up->sessions[i].used)
                any_session = true;
        if (!any_session || !ue_ran_transport_is_connected(up->transport))
            return 0;
    }

    /*
     * Drain all pending downlink data PDUs from RAN transport.
     *
     * UERANSIM path: RLS PDU_TRANSMISSION(DATA) received
     *   → NmUeRlsToNas(DATA_PDU_DELIVERY, psi, pdu)
     *   → NasTask/SM → NmUeNasToApp(DATA_PDU_DELIVERY)
     *   → AppTask → NmAppToTun(DATA_PDU_DELIVERY)
     *   → TunTask → write(tun_fd, pdu)
     *
     * We do: ue_ran_transport_recv_data_pdu() → dl_callback(psi, pdu)
     */
    while ((pkt_len = ue_ran_transport_recv_data_pdu(up->transport,
                                                     &psi,
                                                     pkt_buf,
                                                     sizeof(pkt_buf))) > 0) {
        if (psi != up->host_psi) {
            if (psi >= 1 && psi <= 15 && up->sessions[psi].used &&
                !up->sessions[psi].host_visible && up->internal_dl_callback) {
                if (up->internal_dl_callback(psi, pkt_buf, (size_t)pkt_len,
                                             up->internal_dl_callback_data) == 0) {
                    delivered++;
                    continue;
                }
            }
            up->dl_drops++;
            continue;
        }

        if (up->dl_callback) {
            if (up->dl_callback(psi, pkt_buf, (size_t)pkt_len,
                                up->dl_callback_data) < 0) {
                up->dl_drops++;
                continue;
            }
        } else {
            up->dl_drops++;
            continue;
        }

        up->dl_packets++;
        up->dl_bytes += (uint64_t)pkt_len;
        delivered++;
    }

    return delivered;
}

int ue_up_tick(struct ue_up_ctx *up, uint64_t now_ms)
{
    (void)now_ms;

    if (!up)
        return -1;

    /* State transitions based on transport availability */
    if (up->has_session && up->transport) {
        bool connected = ue_ran_transport_is_connected(up->transport);

        if (up->state == UE_UP_BINDING && connected)
            up->state = UE_UP_ACTIVE;
        else if (up->state == UE_UP_ACTIVE && !connected)
            up->state = UE_UP_SUSPENDED;
        else if (up->state == UE_UP_SUSPENDED && connected)
            up->state = UE_UP_ACTIVE;
    }

    /*
     * Downlink draining runs on the RLS receive thread (registered as the
     * transport on_data_rx callback), not on this engine tick — see
     * dataplane-thread-decoupling. Both host and internal (IMS) sessions are
     * routed there by ue_up_process_downlink.
     */

    return 0;
}

void ue_up_suspend(struct ue_up_ctx *up)
{
    if (!up)
        return;
    if (up->state == UE_UP_ACTIVE)
        up->state = UE_UP_SUSPENDED;
}

void ue_up_resume(struct ue_up_ctx *up)
{
    if (!up)
        return;
    if (up->state == UE_UP_SUSPENDED)
        up->state = UE_UP_ACTIVE;
}

void ue_up_deinit(struct ue_up_ctx *up)
{
    if (!up)
        return;
    ue_up_unbind_session(up);
    memset(up, 0, sizeof(*up));
}

bool ue_up_is_active(const struct ue_up_ctx *up)
{
    return up && up->state == UE_UP_ACTIVE && up->has_session;
}

const struct ue_up_session *ue_up_get_session(const struct ue_up_ctx *up)
{
    if (!up || !up->has_session)
        return NULL;
    return &up->session;
}
