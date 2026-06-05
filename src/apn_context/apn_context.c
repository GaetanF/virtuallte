#include "apn_context.h"

#include <strings.h>
#include <string.h>
#include <stdio.h>

#include "../common/log.h"

void apn_context_manager_init(struct apn_context_manager *mgr, bool ims_enabled)
{
    if (!mgr)
        return;
    memset(mgr, 0, sizeof(*mgr));
    mgr->ims_enabled = ims_enabled;
    mgr->next_id = 1;
}

enum apn_context_kind apn_context_classify(const struct apn_context_manager *mgr,
                                           const char *apn)
{
    if (mgr && mgr->ims_enabled && apn && !strcasecmp(apn, "ims"))
        return APN_CONTEXT_IMS_INTERNAL;
    return APN_CONTEXT_HOST_DATA;
}

static struct apn_context *find_by_apn(struct apn_context_manager *mgr, const char *apn)
{
    if (!mgr || !apn || apn[0] == '\0')
        return NULL;
    for (int i = 0; i < APN_CONTEXT_MAX; i++) {
        if (mgr->contexts[i].used && !strcasecmp(mgr->contexts[i].apn, apn))
            return &mgr->contexts[i];
    }
    return NULL;
}

int apn_context_upsert(struct apn_context_manager *mgr,
                       const char *apn,
                       enum apn_context_ip_type ip_type,
                       enum apn_context_source source,
                       uint32_t *out_id)
{
    struct apn_context *ctx;

    if (out_id)
        *out_id = 0;
    if (!mgr || !apn || apn[0] == '\0')
        return -1;

    ctx = find_by_apn(mgr, apn);
    if (!ctx) {
        for (int i = 0; i < APN_CONTEXT_MAX; i++) {
            if (!mgr->contexts[i].used) {
                ctx = &mgr->contexts[i];
                memset(ctx, 0, sizeof(*ctx));
                ctx->used = true;
                ctx->id = mgr->next_id++;
                snprintf(ctx->apn, sizeof(ctx->apn), "%s", apn);
                break;
            }
        }
    }
    if (!ctx)
        return -1;

    ctx->ip_type = ip_type ? ip_type : APN_CONTEXT_IP_TYPE_IPV4;
    ctx->source = source;
    ctx->kind = apn_context_classify(mgr, apn);
    if (out_id)
        *out_id = ctx->id;

    LOG_INF(CORE, "APN context upsert id=%u apn=%s kind=%s source=%u ip_type=%u",
            ctx->id, ctx->apn,
            ctx->kind == APN_CONTEXT_IMS_INTERNAL ? "ims-internal" : "host-data",
            ctx->source, ctx->ip_type);
    return 0;
}

const struct apn_context *apn_context_get_ims(const struct apn_context_manager *mgr)
{
    if (!mgr)
        return NULL;
    for (int i = 0; i < APN_CONTEXT_MAX; i++) {
        if (mgr->contexts[i].used && mgr->contexts[i].kind == APN_CONTEXT_IMS_INTERNAL)
            return &mgr->contexts[i];
    }
    return NULL;
}

const struct apn_context *apn_context_get_by_id(const struct apn_context_manager *mgr,
                                                uint32_t id)
{
    if (!mgr || id == 0)
        return NULL;
    for (int i = 0; i < APN_CONTEXT_MAX; i++) {
        if (mgr->contexts[i].used && mgr->contexts[i].id == id)
            return &mgr->contexts[i];
    }
    return NULL;
}
