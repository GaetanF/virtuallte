#ifndef STATE_BRIDGE_H
#define STATE_BRIDGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../runtime/ue_instance_config.h"
#include "../apn_context/apn_context.h"

struct state_bridge;
struct ue_engine;
struct ue_instance_config;

enum mbim_bridge_indication {
    MBIM_BRIDGE_IND_NONE = 0,
    MBIM_BRIDGE_IND_REGISTER_SEARCHING,
    MBIM_BRIDGE_IND_REGISTER_DEREGISTERED,
    MBIM_BRIDGE_IND_REGISTER_HOME,
    MBIM_BRIDGE_IND_PACKET_ATTACHING,
    MBIM_BRIDGE_IND_PACKET_ATTACHED,
    MBIM_BRIDGE_IND_PACKET_DETACHED,
};

int state_bridge_init(struct state_bridge **out_bridge);
int state_bridge_init_with_config(struct state_bridge **out_bridge,
                                  const struct ue_instance_config *cfg);
void state_bridge_destroy(struct state_bridge *bridge);

int state_bridge_init_default(void);
int state_bridge_init_default_with_config(const struct ue_instance_config *cfg);
void state_bridge_shutdown_default(void);

int state_bridge_poll(void);
int state_bridge_set_radio(bool on);
int state_bridge_request_register(void);
int state_bridge_request_connect(const char *apn);
int state_bridge_request_disconnect(void);
enum mbim_bridge_indication state_bridge_next_indication(void);
bool state_bridge_has_pending_indication(void);

/* SMS over IMS (IMS-only: no SMS-over-NAS path). */
int state_bridge_send_sms_ims(const uint8_t *sms_pdu, size_t sms_pdu_len,
                              uint32_t *reference);
int state_bridge_upsert_apn_context(const char *apn,
                                    enum apn_context_ip_type ip_type,
                                    enum apn_context_source source,
                                    uint32_t *out_id);
bool state_bridge_has_ims_context(void);
bool state_bridge_has_pending_sms(void);
bool state_bridge_pop_sms(uint8_t *out, size_t out_cap, size_t *out_len);
bool state_bridge_ims_enabled(void);
bool state_bridge_sms_enabled(void);
enum ue_sms_transport_mode state_bridge_sms_transport(void);
bool state_bridge_ims_registered(void);

struct ue_engine *state_bridge_default_engine(void);

/*
 * Downlink data delivery callback type.
 * Called by the UE user plane when downlink IP packets arrive.
 * The callback should write the packet to the MBIM data endpoint.
 *
 * psi: PDU Session Identity
 * data: raw IP packet
 * len: packet length
 * user_data: opaque pointer (e.g. to core_runtime_context)
 *
 * Returns 0 on success, -1 on error.
 */
typedef int (*state_bridge_dl_cb)(int psi, const uint8_t *data,
                                  size_t len, void *user_data);

/*
 * Register a downlink data delivery callback.
 * This connects the UE user plane to the MBIM USB data endpoint.
 * Must be called after state_bridge_init_default.
 */
int state_bridge_set_downlink_callback(state_bridge_dl_cb cb, void *user_data);

#endif
