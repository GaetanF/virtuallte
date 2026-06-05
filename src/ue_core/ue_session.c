#include "ue_session.h"

#include <string.h>

void ue_session_set_default_ip(struct ue_context *ctx)
{
    strcpy(ctx->active_dnn, ctx->cfg.network.dnn);
    ctx->ip.ipv4_addr[0] = 1;
    ctx->ip.ipv4_addr[1] = 2;
    ctx->ip.ipv4_addr[2] = 3;
    ctx->ip.ipv4_addr[3] = 4;
    ctx->ip.ipv4_gw[0] = 5;
    ctx->ip.ipv4_gw[1] = 6;
    ctx->ip.ipv4_gw[2] = 7;
    ctx->ip.ipv4_gw[3] = 8;
    ctx->ip.dns1[0] = 9;
    ctx->ip.dns1[1] = 10;
    ctx->ip.dns1[2] = 11;
    ctx->ip.dns1[3] = 12;
    ctx->ip.dns2[0] = 1;
    ctx->ip.dns2[1] = 1;
    ctx->ip.dns2[2] = 1;
    ctx->ip.dns2[3] = 1;
    ctx->ip.mtu = 1500;
}
