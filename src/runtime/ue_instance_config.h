#ifndef UE_INSTANCE_CONFIG_H
#define UE_INSTANCE_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

struct ue_device_identity {
    char imei[32];
    char manufacturer[64];
    char model[64];
    char firmware[64];
    char serial[64];
};

struct ue_sim_profile {
    bool sim_present;
    char imsi[32];
    char iccid[40];
    char key[64];
    char opc[64];
    char amf[16];
};

struct ue_network_profile {
    char mcc[8];
    char mnc[8];
    char dnn[64];
    char operator_long[64];
    char operator_short[32];
    char pdu_type[16];
    uint8_t slice_sst;              /* S-NSSAI SST: 0=omit, 1=eMBB */
};

struct ue_logging_config {
    char level[16];
    int domain_count;
    char domain_names[16][32];
    char domain_levels[16][16];
};

struct ue_ran_config {
    char gnb_address[128];
    uint16_t gnb_port;
};

enum ue_sms_transport_mode {
    UE_SMS_TRANSPORT_AUTO = 0,
    UE_SMS_TRANSPORT_IMS,
    /* SMS over NAS is not supported (IMS-only); the "nas" config value is
     * rejected by the parser. */
};

struct ue_ims_config {
    bool enabled;
};

struct ue_sms_config {
    bool enabled;
    enum ue_sms_transport_mode transport;
};

struct ue_instance_config {
    struct ue_device_identity device;
    struct ue_sim_profile sim;
    struct ue_network_profile network;
    struct ue_ran_config ran;
    struct ue_ims_config ims;
    struct ue_sms_config sms;
    struct ue_logging_config logging;
    bool use_real_backend;
};

int ue_instance_config_set_defaults(struct ue_instance_config *cfg);
int ue_instance_config_load_file(struct ue_instance_config *cfg, const char *path);
int ue_instance_config_validate(const struct ue_instance_config *cfg);
int ue_instance_config_finalize(struct ue_instance_config *cfg,
                                unsigned int ue_id,
                                bool allow_lab_autogen_subscriber);

#endif
