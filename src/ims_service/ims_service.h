#ifndef IMS_SERVICE_H
#define IMS_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../runtime/ue_instance_config.h"

struct ims_service;

typedef int (*ims_service_tx_ip_cb)(const uint8_t *packet,
                                    size_t packet_len,
                                    void *user_data);
typedef int (*ims_service_sms_downlink_cb)(const uint8_t *pdu,
                                           size_t pdu_len,
                                           void *user_data);

int ims_service_init(struct ims_service **out,
                     const struct ue_instance_config *cfg);
void ims_service_destroy(struct ims_service *svc);

bool ims_service_enabled(const struct ims_service *svc);
bool ims_service_registered(struct ims_service *svc);
void ims_service_set_pdu_active(struct ims_service *svc,
                                bool active,
                                const uint8_t ipv4[4],
                                bool has_pcscf,
                                const uint8_t pcscf_ipv4[4]);
void ims_service_set_tx_callback(struct ims_service *svc,
                                 ims_service_tx_ip_cb cb,
                                 void *user_data);
void ims_service_set_sms_downlink_callback(struct ims_service *svc,
                                           ims_service_sms_downlink_cb cb,
                                           void *user_data);

int ims_service_submit_sms(struct ims_service *svc,
                           const uint8_t *pdu,
                           size_t pdu_len,
                           uint32_t *reference);
int ims_service_receive_ip(struct ims_service *svc,
                           int psi,
                           const uint8_t *packet,
                           size_t packet_len);

#endif
