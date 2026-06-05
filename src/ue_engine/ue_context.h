#ifndef UE_ENGINE_CONTEXT_H
#define UE_ENGINE_CONTEXT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../runtime/ue_instance_config.h"
#include "ue_mm.h"
#include "ue_nas_security.h"
#include "ue_ran_transport.h"
#include "ue_sm.h"
#include "ue_types.h"
#include "ue_up.h"

/*
 * RRC connection state. Tracks whether an RRC connection is established
 * with the gNB.
 */
enum ue_rrc_state {
    UE_RRC_IDLE = 0,          /* no RRC connection */
    UE_RRC_SETUP_REQUESTED,   /* RRCSetupRequest sent, awaiting RRCSetup */
    UE_RRC_CONNECTED,         /* RRC connection established */
};

struct ue_context {
    uint32_t ue_id;
    bool running;
    bool radio_on;
    bool sim_ready;

    struct ue_instance_config cfg;
    struct ue_mm_ctx mm;
    struct ue_sm_ctx sm;

    /* User plane data path (target: real IP traffic) */
    struct ue_up_ctx up;

    /* RAN transport toward gNB (target: real RLS/UDP) */
    struct ue_ran_transport_ctx ran;

    /* RRC connection state */
    enum ue_rrc_state rrc_state;
    uint64_t rrc_setup_request_ms;  /* timestamp of last RRCSetupRequest */

    /* Post-RRCSetupComplete tracking (REAL backend) */
    uint64_t rrc_setup_complete_ms;  /* timestamp of RRCSetupComplete sent */
    uint32_t post_setup_pdu_count;   /* PDUs received after RRCSetupComplete */
    bool waiting_core_response;      /* true = waiting for AMF/core response */

    /* NAS security context (REAL backend) */
    struct ue_nas_security_ctx nas_sec;
    struct ue_nas_security_ctx nas_sec_non_current;
    bool nas_sec_non_current_valid;

    /* Last protected DL NAS envelope (for SMC replay handling) */
    bool dl_sec_hdr_valid;
    uint8_t dl_sec_hdr_sht;
    uint32_t dl_sec_hdr_mac;
    uint8_t dl_sec_hdr_sqn;

    /* Last processed Security Mode Command fingerprint */
    bool smc_last_valid;
    uint32_t smc_last_mac;
    uint8_t smc_last_sqn;
    uint8_t smc_last_algs;
    uint8_t smc_last_ngksi;
    uint8_t smc_last_inner[256];
    size_t smc_last_inner_len;
    uint8_t smc_last_payload[256];
    size_t smc_last_payload_len;

    /* Stored 5G-GUTI (raw 5GS mobile identity value from Registration Accept).
     * When valid, replayed as the mobile identity in later Registration
     * Requests instead of the SUCI. */
    uint8_t guti[16];
    size_t guti_len;

    /* AKA: highest accepted SQN (48-bit, big-endian) for resync detection. */
    uint8_t auth_sqn_ms[6];
    bool auth_sqn_ms_valid;

    /* ngKSI assigned by the network (Authentication Request), reused in
     * subsequent (mobility/periodic) Registration Requests. */
    uint8_t reg_ngksi;
    bool reg_ngksi_valid;

    /* T3512 periodic registration timer value (seconds) from Reg. Accept. */
    uint32_t t3512_seconds;

    /*
     * Internal IMS PDU session (SMS over IMS). Not exposed to the MBIM host;
     * IP packets are produced/consumed in userspace by ims_service and routed
     * over the RLS DATA path on ims_psi.
     */
    bool ims_pdu_requested;
    bool ims_pdu_establishing;
    bool ims_pdu_active;
    bool ims_has_pcscf;
    uint8_t ims_psi;
    uint8_t ims_pti;
    uint8_t ims_pcscf_ipv4[4];
    struct ue_engine_runtime_ip ims_ip;

    struct ue_engine_snapshot snapshot;
    uint32_t changed_flags;
};

int ue_context_init_from_config(struct ue_context *ctx,
                                uint32_t ue_id,
                                const struct ue_instance_config *cfg);
void ue_context_refresh_snapshot(struct ue_context *ctx);

#endif
