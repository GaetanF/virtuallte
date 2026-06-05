#ifndef UE_NAS_H
#define UE_NAS_H

#include <stdbool.h>
#include <stdint.h>

#include "ue_context.h"

int ue_core_init(struct ue_context *ctx,
                 uint32_t ue_id,
                 const struct ue_instance_config *cfg);
int ue_core_start(struct ue_context *ctx);
int ue_core_stop(struct ue_context *ctx);
int ue_core_tick(struct ue_context *ctx, uint64_t now_ms);
int ue_core_set_radio(struct ue_context *ctx, bool on);
int ue_core_request_register(struct ue_context *ctx);
int ue_core_request_connect(struct ue_context *ctx, const char *dnn);
int ue_core_request_disconnect(struct ue_context *ctx);

#endif
