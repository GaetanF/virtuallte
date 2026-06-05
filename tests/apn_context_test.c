#include "../src/apn_context/apn_context.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    struct apn_context_manager mgr;
    const struct apn_context *ims;
    uint32_t id = 0;

    apn_context_manager_init(&mgr, true);

    assert(apn_context_classify(&mgr, "internet") == APN_CONTEXT_HOST_DATA);
    assert(apn_context_classify(&mgr, "ims") == APN_CONTEXT_IMS_INTERNAL);
    assert(apn_context_classify(&mgr, "IMS") == APN_CONTEXT_IMS_INTERNAL);

    assert(apn_context_upsert(&mgr, "internet", APN_CONTEXT_IP_TYPE_IPV4,
                               APN_CONTEXT_SOURCE_HOST_CONNECT, &id) == 0);
    assert(id != 0);
    assert(apn_context_get_by_id(&mgr, id) != NULL);
    assert(apn_context_get_by_id(&mgr, id)->kind == APN_CONTEXT_HOST_DATA);

    assert(apn_context_upsert(&mgr, "ims", APN_CONTEXT_IP_TYPE_IPV4,
                               APN_CONTEXT_SOURCE_HOST_PROVISIONED, &id) == 0);
    ims = apn_context_get_ims(&mgr);
    assert(ims != NULL);
    assert(!strcmp(ims->apn, "ims"));
    assert(ims->kind == APN_CONTEXT_IMS_INTERNAL);

    apn_context_manager_init(&mgr, false);
    assert(apn_context_classify(&mgr, "ims") == APN_CONTEXT_HOST_DATA);

    return 0;
}
