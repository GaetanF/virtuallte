#include "ue_instance_config.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static int is_empty(const char *s)
{
    return !s || s[0] == '\0';
}

static char *trim(char *s)
{
    char *end;

    while (*s && isspace((unsigned char)*s))
        s++;

    if (*s == '\0')
        return s;

    end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end))
        end--;
    end[1] = '\0';

    return s;
}

static int parse_bool(const char *s, bool *out)
{
    if (!s || !out)
        return -1;

    if (!strcasecmp(s, "1") || !strcasecmp(s, "true") || !strcasecmp(s, "yes") || !strcasecmp(s, "on")) {
        *out = true;
        return 0;
    }

    if (!strcasecmp(s, "0") || !strcasecmp(s, "false") || !strcasecmp(s, "no") || !strcasecmp(s, "off")) {
        *out = false;
        return 0;
    }

    return -1;
}

static int parse_sms_transport(const char *s, enum ue_sms_transport_mode *out)
{
    if (!s || !out)
        return -1;
    if (!strcasecmp(s, "auto")) {
        *out = UE_SMS_TRANSPORT_AUTO;
        return 0;
    }
    if (!strcasecmp(s, "ims")) {
        *out = UE_SMS_TRANSPORT_IMS;
        return 0;
    }
    /* "nas" is intentionally unsupported (IMS-only) -> rejected. */
    return -1;
}

int ue_instance_config_load_file(struct ue_instance_config *cfg, const char *path)
{
    FILE *f;
    char line[512];
    char section[32] = "";

    if (!cfg || !path)
        return -1;

    f = fopen(path, "r");
    if (!f)
        return -errno;

    while (fgets(line, sizeof(line), f)) {
        char *s = trim(line);
        char *eq;
        char *key;
        char *value;

        if (*s == '\0' || *s == '#' || *s == ';')
            continue;

        if (*s == '[') {
            char *close = strchr(s, ']');
            if (!close)
                continue;
            *close = '\0';
            snprintf(section, sizeof(section), "%s", trim(s + 1));
            continue;
        }

        eq = strchr(s, '=');
        if (!eq)
            continue;

        *eq = '\0';
        key = trim(s);
        value = trim(eq + 1);

        if (!strcasecmp(section, "device")) {
            if (!strcasecmp(key, "imei"))
                snprintf(cfg->device.imei, sizeof(cfg->device.imei), "%s", value);
            else if (!strcasecmp(key, "manufacturer"))
                snprintf(cfg->device.manufacturer, sizeof(cfg->device.manufacturer), "%s", value);
            else if (!strcasecmp(key, "model"))
                snprintf(cfg->device.model, sizeof(cfg->device.model), "%s", value);
            else if (!strcasecmp(key, "firmware"))
                snprintf(cfg->device.firmware, sizeof(cfg->device.firmware), "%s", value);
            else if (!strcasecmp(key, "serial"))
                snprintf(cfg->device.serial, sizeof(cfg->device.serial), "%s", value);
        } else if (!strcasecmp(section, "sim")) {
            if (!strcasecmp(key, "imsi"))
                snprintf(cfg->sim.imsi, sizeof(cfg->sim.imsi), "%s", value);
            else if (!strcasecmp(key, "iccid"))
                snprintf(cfg->sim.iccid, sizeof(cfg->sim.iccid), "%s", value);
            else if (!strcasecmp(key, "key"))
                snprintf(cfg->sim.key, sizeof(cfg->sim.key), "%s", value);
            else if (!strcasecmp(key, "opc") || !strcasecmp(key, "op"))
                snprintf(cfg->sim.opc, sizeof(cfg->sim.opc), "%s", value);
            else if (!strcasecmp(key, "amf"))
                snprintf(cfg->sim.amf, sizeof(cfg->sim.amf), "%s", value);
            else if (!strcasecmp(key, "sim_present")) {
                bool b;
                if (parse_bool(value, &b) == 0)
                    cfg->sim.sim_present = b;
            }
        } else if (!strcasecmp(section, "network")) {
            if (!strcasecmp(key, "mcc"))
                snprintf(cfg->network.mcc, sizeof(cfg->network.mcc), "%s", value);
            else if (!strcasecmp(key, "mnc"))
                snprintf(cfg->network.mnc, sizeof(cfg->network.mnc), "%s", value);
            else if (!strcasecmp(key, "dnn") || !strcasecmp(key, "apn"))
                snprintf(cfg->network.dnn, sizeof(cfg->network.dnn), "%s", value);
            else if (!strcasecmp(key, "operator_long"))
                snprintf(cfg->network.operator_long, sizeof(cfg->network.operator_long), "%s", value);
            else if (!strcasecmp(key, "operator_short"))
                snprintf(cfg->network.operator_short, sizeof(cfg->network.operator_short), "%s", value);
            else if (!strcasecmp(key, "pdu_type"))
                snprintf(cfg->network.pdu_type, sizeof(cfg->network.pdu_type), "%s", value);
            else if (!strcasecmp(key, "slice_sst"))
                cfg->network.slice_sst = (uint8_t)atoi(value);
        } else if (!strcasecmp(section, "backend")) {
            if (!strcasecmp(key, "mode")) {
                bool b;
                if (parse_bool(value, &b) == 0)
                    cfg->use_real_backend = b;
                else if (!strcasecmp(value, "real") || !strcasecmp(value, "true") || !strcasecmp(value, "1") || !strcasecmp(value, "yes") || !strcasecmp(value, "on"))
                    cfg->use_real_backend = true;
                else
                    cfg->use_real_backend = false;
            }
        } else if (!strcasecmp(section, "ran")) {
            if (!strcasecmp(key, "gnb_address"))
                snprintf(cfg->ran.gnb_address, sizeof(cfg->ran.gnb_address), "%s", value);
            else if (!strcasecmp(key, "gnb_port"))
                cfg->ran.gnb_port = (uint16_t)atoi(value);
        } else if (!strcasecmp(section, "ims")) {
            if (!strcasecmp(key, "enabled")) {
                bool b;
                if (parse_bool(value, &b) == 0)
                    cfg->ims.enabled = b;
            }
        } else if (!strcasecmp(section, "sms")) {
            if (!strcasecmp(key, "enabled")) {
                bool b;
                if (parse_bool(value, &b) == 0)
                    cfg->sms.enabled = b;
            } else if (!strcasecmp(key, "transport")) {
                enum ue_sms_transport_mode mode;
                if (parse_sms_transport(value, &mode) == 0)
                    cfg->sms.transport = mode;
            }
        } else if (!strcasecmp(section, "logging")) {
            if (!strcasecmp(key, "level"))
                snprintf(cfg->logging.level, sizeof(cfg->logging.level), "%s", value);
        } else if (!strcasecmp(section, "logging.domains")) {
            if (cfg->logging.domain_count < 16) {
                int idx = cfg->logging.domain_count;
                snprintf(cfg->logging.domain_names[idx],
                         sizeof(cfg->logging.domain_names[idx]), "%s", key);
                snprintf(cfg->logging.domain_levels[idx],
                         sizeof(cfg->logging.domain_levels[idx]), "%s", value);
                cfg->logging.domain_count++;
            }
        }
    }

    fclose(f);
    return 0;
}

int ue_instance_config_set_defaults(struct ue_instance_config *cfg)
{
    if (!cfg)
        return -1;

    memset(cfg, 0, sizeof(*cfg));

    snprintf(cfg->device.manufacturer, sizeof(cfg->device.manufacturer), "%s", "Quectel");
    snprintf(cfg->device.model, sizeof(cfg->device.model), "%s", "RM520N-GL");
    snprintf(cfg->device.firmware, sizeof(cfg->device.firmware), "%s", "FAKA01");
    snprintf(cfg->device.serial, sizeof(cfg->device.serial), "%s", "deadbeef0001");

    cfg->sim.sim_present = true;
    snprintf(cfg->sim.imsi, sizeof(cfg->sim.imsi), "%s", "208010123456789");
    snprintf(cfg->sim.iccid, sizeof(cfg->sim.iccid), "%s", "8933012345678901234");
    snprintf(cfg->sim.key, sizeof(cfg->sim.key), "%s", "00112233445566778899aabbccddeeff");
    snprintf(cfg->sim.opc, sizeof(cfg->sim.opc), "%s", "63bfa50ee6523365ff14c1f45f88737d");
    snprintf(cfg->sim.amf, sizeof(cfg->sim.amf), "%s", "8000");

    snprintf(cfg->network.mcc, sizeof(cfg->network.mcc), "%s", "208");
    snprintf(cfg->network.mnc, sizeof(cfg->network.mnc), "%s", "01");
    snprintf(cfg->network.dnn, sizeof(cfg->network.dnn), "%s", "internet");
    snprintf(cfg->network.operator_long, sizeof(cfg->network.operator_long), "%s", "EllaLab");
    snprintf(cfg->network.operator_short, sizeof(cfg->network.operator_short), "%s", "EllaLab");
    snprintf(cfg->network.pdu_type, sizeof(cfg->network.pdu_type), "%s", "ipv4");
    cfg->network.slice_sst = 1;  /* default: eMBB */

    snprintf(cfg->ran.gnb_address, sizeof(cfg->ran.gnb_address), "%s", "127.0.0.1");
    cfg->ran.gnb_port = 4997;

    /* SMS over IMS only: enable IMS + SMS and force the IMS transport. */
    cfg->ims.enabled = true;
    cfg->sms.enabled = true;
    cfg->sms.transport = UE_SMS_TRANSPORT_IMS;

    cfg->use_real_backend = false;

    return 0;
}

int ue_instance_config_validate(const struct ue_instance_config *cfg)
{
    if (!cfg)
        return -1;

    if (is_empty(cfg->device.manufacturer) ||
        is_empty(cfg->device.model) ||
        is_empty(cfg->device.firmware))
        return -1;

    if (cfg->sim.sim_present) {
        if (is_empty(cfg->sim.imsi) || is_empty(cfg->sim.iccid) ||
            is_empty(cfg->sim.key) || is_empty(cfg->sim.opc) || is_empty(cfg->sim.amf))
            return -1;
    }

    if (is_empty(cfg->network.mcc) || is_empty(cfg->network.mnc) ||
        is_empty(cfg->network.dnn) || is_empty(cfg->network.operator_long))
        return -1;

    return 0;
}

int ue_instance_config_finalize(struct ue_instance_config *cfg,
                                unsigned int ue_id,
                                bool allow_lab_autogen_subscriber)
{
    if (!cfg)
        return -1;

    if (is_empty(cfg->device.imei))
        snprintf(cfg->device.imei, sizeof(cfg->device.imei), "8675309%08u", ue_id % 100000000U);

    if (allow_lab_autogen_subscriber && cfg->sim.sim_present) {
        if (is_empty(cfg->sim.imsi))
            snprintf(cfg->sim.imsi, sizeof(cfg->sim.imsi), "00101%010u", ue_id % 1000000000U);
        if (is_empty(cfg->sim.iccid))
            snprintf(cfg->sim.iccid, sizeof(cfg->sim.iccid), "890100100000%07u", ue_id % 10000000U);
    }

    return ue_instance_config_validate(cfg);
}
