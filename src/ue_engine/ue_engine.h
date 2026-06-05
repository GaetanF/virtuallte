#ifndef UE_ENGINE_H
#define UE_ENGINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../runtime/ue_instance_config.h"
#include "ue_context.h"

struct ue_engine {
    struct ue_context ctx;
};

int ue_engine_init(struct ue_engine *engine,
                   const struct ue_instance_config *cfg,
                   uint32_t ue_id);
void ue_engine_deinit(struct ue_engine *engine);

int ue_engine_start(struct ue_engine *engine);
int ue_engine_stop(struct ue_engine *engine);

int ue_engine_tick(struct ue_engine *engine, uint64_t now_ms);

int ue_engine_set_radio(struct ue_engine *engine, bool on);
int ue_engine_request_register(struct ue_engine *engine);
int ue_engine_request_periodic_update(struct ue_engine *engine);
int ue_engine_request_mobility_update(struct ue_engine *engine);
int ue_engine_request_connect(struct ue_engine *engine, const char *dnn);
int ue_engine_request_disconnect(struct ue_engine *engine);
int ue_engine_request_ims_pdu(struct ue_engine *engine);
int ue_engine_inject_uplink_ip(struct ue_engine *engine,
                               const uint8_t *ip_packet,
                               size_t len);
int ue_engine_inject_ims_ip(struct ue_engine *engine,
                            const uint8_t *ip_packet,
                            size_t len);

const struct ue_engine_snapshot *ue_engine_snapshot(const struct ue_engine *engine);
uint32_t ue_engine_take_changed(struct ue_engine *engine);

#endif
