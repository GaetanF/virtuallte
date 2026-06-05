#ifndef UE_ENGINE_NETWORK_ADAPTER_H
#define UE_ENGINE_NETWORK_ADAPTER_H

/*
 * ue_network_adapter - Seam where MM/SM submit network operations.
 *
 * The adapter encodes the requested NAS message, protects it (when a NAS
 * security context is active), wraps it in an RRC ULInformationTransfer and
 * sends it to the gNB via ue_ran_transport. Submits return {submitted=true}
 * as a placeholder; the real accept/reject arrives asynchronously via a
 * downlink NAS PDU handled in ue_engine.
 */

#include <stdbool.h>

#include "ue_mm_messages.h"
#include "ue_sm_messages.h"

struct ue_ran_transport_ctx;
struct ue_nas_security_ctx;

/* Submit MM REGISTRATION REQUEST via RAN transport. */
struct ue_mm_registration_result ue_network_mm_submit_registration(
    const struct ue_mm_registration_request *req);

/* Submit PDU SESSION ESTABLISHMENT REQUEST via RAN transport. */
struct ue_sm_pdu_session_est_result ue_network_sm_submit_establish(
    const struct ue_sm_pdu_session_est_request *req);

/* Submit PDU SESSION RELEASE REQUEST via RAN transport. */
struct ue_sm_pdu_session_rel_result ue_network_sm_submit_release(
    const struct ue_sm_pdu_session_rel_request *req);

/*
 * Wire the adapter to the real RAN transport. Must be called before any
 * submit. Passing NULL disables uplink (submits return not-submitted).
 */
void ue_network_adapter_set_transport(struct ue_ran_transport_ctx *transport);

/*
 * Set NAS security context used for uplink sends. If set and active,
 * outgoing NAS is protected before RRC wrapping.
 */
void ue_network_adapter_set_security_ctx(struct ue_nas_security_ctx *nas_sec);

#endif
