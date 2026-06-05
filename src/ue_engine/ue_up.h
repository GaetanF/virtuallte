#ifndef UE_UP_H
#define UE_UP_H

/*
 * ue_up - UE User Plane: real data path for IP traffic through 5G.
 *
 * UERANSIM anchor:
 *   - src/ue/tun/task.hpp       : TUN device read/write (IP packet I/O)
 *   - src/ue/app/task.hpp       : App layer routing TUN ↔ NAS SM
 *   - src/ue/nas/sm/transport.cpp : SM data PDU routing to RLS
 *   - src/ue/nts.hpp            : NmUeTunToApp, NmUeNasToRls messages
 *   - src/ue/types.hpp          : PduSession structure
 *
 * This module owns the per-session user plane data path.
 * It sits between:
 *   - upstream:   MBIM frontend / USB data endpoint (replaces TUN)
 *   - downstream: ue_ran_transport (RLS PDU_TRANSMISSION with DATA type)
 *
 * In the target architecture:
 *   Host/RouterOS → MBIM USB → ue_up (uplink) → ue_ran_transport → gNB → 5GC
 *   5GC → gNB → ue_ran_transport → ue_up (downlink) → MBIM USB → Host/RouterOS
 *
 * NOT a TUN device. The MBIM USB gadget is the data interface to the host.
 * ue_up handles the internal routing, not the host-facing I/O.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ue_types.h"

/*
 * Forward declarations - ue_up needs pointers to transport for send/recv.
 */
struct ue_ran_transport_ctx;

/*
 * User plane data path state.
 */
enum ue_up_state {
    UE_UP_IDLE = 0,     /* no active PDU session, no data path       */
    UE_UP_BINDING,       /* PDU session accepted, configuring path    */
    UE_UP_ACTIVE,        /* data path ready, forwarding traffic       */
    UE_UP_SUSPENDED,     /* data path paused (e.g. RAN transport lost)*/
};

/*
 * Per-session user plane context.
 * Mirrors UERANSIM PduSession (src/ue/types.hpp) for the data plane subset.
 *
 * fake_mbim simplification: one active session at a time (MBIM constraint).
 * UERANSIM supports up to 15 concurrent sessions; we support one.
 */
struct ue_up_session {
    bool used;
    bool host_visible;
    int psi;                     /* PDU Session ID (1-15)          */
    char dnn[64];                /* Data Network Name              */
    char pdu_type[16];           /* "ipv4", "ipv6", "ipv4v6"      */

    /* IP configuration assigned by the network */
    uint8_t ipv4_addr[4];
    uint8_t ipv4_gw[4];
    uint8_t dns1[4];
    uint8_t dns2[4];
    uint32_t mtu;

    /* QoS (future: populated from SM QoS rules) */
    uint32_t ambr_ul_kbps;       /* aggregate max bitrate uplink   */
    uint32_t ambr_dl_kbps;       /* aggregate max bitrate downlink */
};

/*
 * Callback for downlink data delivery to MBIM frontend.
 * Called by ue_up when a data PDU arrives from the RAN.
 *
 * This replaces UERANSIM's TUN write path.
 * The MBIM frontend registers this callback to receive IP packets
 * that should be sent to the host via the USB data endpoint.
 *
 * psi:  PDU Session ID
 * data: raw IP packet
 * len:  packet length
 * user_data: opaque pointer set at registration
 *
 * Returns 0 on success, -1 if the frontend cannot accept the packet.
 */
typedef int (*ue_up_downlink_cb)(int psi,
                                 const uint8_t *data, size_t len,
                                 void *user_data);
typedef int (*ue_up_internal_downlink_cb)(int psi,
                                          const uint8_t *data, size_t len,
                                          void *user_data);

/*
 * Main user plane runtime context.
 *
 * Ownership: embedded in ue_context, one per UE instance.
 */
struct ue_up_ctx {
    enum ue_up_state state;

    /* Host-visible active session kept for the MBIM data path. */
    struct ue_up_session session;
    bool has_session;

    /* All PDU sessions indexed by PSI. Internal sessions (e.g. ims) are not
     * exposed to the host but still use the same RLS DATA path. */
    struct ue_up_session sessions[16];
    int host_psi;

    /* Link to RAN transport for data PDU send/recv */
    struct ue_ran_transport_ctx *transport;

    /* Downlink delivery callback (registered by MBIM frontend) */
    ue_up_downlink_cb dl_callback;
    void *dl_callback_data;

    ue_up_internal_downlink_cb internal_dl_callback;
    void *internal_dl_callback_data;

    /* Statistics */
    uint64_t ul_packets;
    uint64_t dl_packets;
    uint64_t ul_bytes;
    uint64_t dl_bytes;
    uint64_t ul_drops;          /* packets dropped (no transport, etc.) */
    uint64_t dl_drops;          /* packets dropped (no callback, etc.)  */
};

/*
 * Initialize user plane context.
 */
void ue_up_init(struct ue_up_ctx *up);

/*
 * Set the RAN transport link.
 * Must be called before ue_up_bind_session().
 */
void ue_up_set_transport(struct ue_up_ctx *up,
                         struct ue_ran_transport_ctx *transport);

/*
 * Register downlink data delivery callback.
 * This is how IP packets from the 5G network reach the MBIM USB frontend.
 */
void ue_up_set_downlink_callback(struct ue_up_ctx *up,
                                 ue_up_downlink_cb cb,
                                 void *user_data);
void ue_up_set_internal_downlink_callback(struct ue_up_ctx *up,
                                          ue_up_internal_downlink_cb cb,
                                          void *user_data);

/*
 * Bind a PDU session to the user plane data path.
 * Called by SM after PDU session establishment accept.
 *
 * UERANSIM anchor: NmUeStatusUpdate(SESSION_ESTABLISHMENT)
 *   → UeAppTask creates TUN, starts TunTask
 *   → data path becomes active
 *
 * Here, we bind the session parameters and transition to ACTIVE.
 * The data path goes through MBIM USB, not TUN.
 */
int ue_up_bind_session(struct ue_up_ctx *up,
                       int psi,
                       const char *dnn,
                       const char *pdu_type,
                       const struct ue_engine_runtime_ip *ip);
int ue_up_bind_session_ex(struct ue_up_ctx *up,
                          int psi,
                          const char *dnn,
                          const char *pdu_type,
                          const struct ue_engine_runtime_ip *ip,
                          bool host_visible);

/*
 * Unbind the current session (PDU session released).
 *
 * UERANSIM anchor: NmUeStatusUpdate(SESSION_RELEASE)
 *   → UeAppTask destroys TUN
 */
void ue_up_unbind_session(struct ue_up_ctx *up);

/* Unbind one PDU session by PSI (e.g. the internal IMS session). */
void ue_up_unbind_session_psi(struct ue_up_ctx *up, int psi);

/*
 * Uplink: inject an IP packet from the MBIM frontend into the 5G data path.
 *
 * This is the uplink entry point. The packet came from the host via USB MBIM.
 * ue_up routes it through ue_ran_transport to the gNB.
 *
 * UERANSIM anchor: TunTask reads IP packet → NmUeTunToApp(DATA_PDU_DELIVERY)
 *   → AppTask → NmUeAppToNas → SM → NmUeNasToRls(DATA_PDU_DELIVERY)
 *
 * Returns 0 on success, -1 on failure (no session, transport down, etc.)
 */
int ue_up_send_uplink(struct ue_up_ctx *up,
                       const uint8_t *ip_packet, size_t len);
int ue_up_send_internal_uplink(struct ue_up_ctx *up,
                               int psi,
                               const uint8_t *ip_packet, size_t len);

/*
 * Downlink: process data PDUs received from RAN transport.
 * Called from ue_engine_tick() or ue_ran_transport_tick() when data arrives.
 *
 * UERANSIM anchor: NmUeRlsToNas(DATA_PDU_DELIVERY)
 *   → SM → NmUeNasToApp → AppTask → NmAppToTun → TunTask writes to TUN
 *
 * Here, we call the registered dl_callback to deliver to MBIM frontend.
 *
 * Returns number of packets delivered, or -1 on error.
 */
int ue_up_process_downlink(struct ue_up_ctx *up);

/*
 * Periodic tick: check transport state, process pending downlink data.
 */
int ue_up_tick(struct ue_up_ctx *up, uint64_t now_ms);

/*
 * Suspend/resume data path (e.g. when RAN transport is lost/recovered).
 */
void ue_up_suspend(struct ue_up_ctx *up);
void ue_up_resume(struct ue_up_ctx *up);

/*
 * Cleanup.
 */
void ue_up_deinit(struct ue_up_ctx *up);

/*
 * Query state.
 */
bool ue_up_is_active(const struct ue_up_ctx *up);
const struct ue_up_session *ue_up_get_session(const struct ue_up_ctx *up);

#endif
