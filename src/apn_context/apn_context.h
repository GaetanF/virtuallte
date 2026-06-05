#ifndef APN_CONTEXT_H
#define APN_CONTEXT_H

#include <stdbool.h>
#include <stdint.h>

#define APN_CONTEXT_APN_MAX 64
#define APN_CONTEXT_MAX     16

enum apn_context_kind {
    APN_CONTEXT_HOST_DATA = 0,
    APN_CONTEXT_IMS_INTERNAL,
};

enum apn_context_source {
    APN_CONTEXT_SOURCE_HOST_PROVISIONED = 0,
    APN_CONTEXT_SOURCE_HOST_LTE_ATTACH,
    APN_CONTEXT_SOURCE_HOST_CONNECT,
    APN_CONTEXT_SOURCE_INTERNAL,
};

enum apn_context_ip_type {
    APN_CONTEXT_IP_TYPE_IPV4 = 1,
    APN_CONTEXT_IP_TYPE_IPV6 = 2,
    APN_CONTEXT_IP_TYPE_IPV4V6 = 3,
};

struct apn_context {
    bool used;
    uint32_t id;
    char apn[APN_CONTEXT_APN_MAX];
    enum apn_context_ip_type ip_type;
    enum apn_context_source source;
    enum apn_context_kind kind;
};

struct apn_context_manager {
    bool ims_enabled;
    uint32_t next_id;
    struct apn_context contexts[APN_CONTEXT_MAX];
};

void apn_context_manager_init(struct apn_context_manager *mgr, bool ims_enabled);
enum apn_context_kind apn_context_classify(const struct apn_context_manager *mgr,
                                           const char *apn);
int apn_context_upsert(struct apn_context_manager *mgr,
                       const char *apn,
                       enum apn_context_ip_type ip_type,
                       enum apn_context_source source,
                       uint32_t *out_id);
const struct apn_context *apn_context_get_ims(const struct apn_context_manager *mgr);
const struct apn_context *apn_context_get_by_id(const struct apn_context_manager *mgr,
                                                uint32_t id);

#endif
