#include "ue_identity.h"

#include <string.h>

void ue_identity_set_defaults(struct ue_context *ctx)
{
    strcpy(ctx->cfg.device.imei, "867530900000001");
    strcpy(ctx->cfg.sim.imsi, "208010123456789");
    strcpy(ctx->cfg.sim.iccid, "8933012345678901234");
}
