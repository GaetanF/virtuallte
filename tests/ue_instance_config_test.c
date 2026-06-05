#include "../src/runtime/ue_instance_config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void write_config_file(const char *path)
{
    FILE *f = fopen(path, "w");
    assert(f);
    fprintf(f,
            "[device]\n"
            "manufacturer = TestMaker\n"
            "model = TestModel\n"
            "firmware = 1.2.3\n"
            "serial = abc123\n"
            "\n"
            "[sim]\n"
            "sim_present = off\n"
            "imsi = 001010000000001\n"
            "iccid = 8901000000000000001\n"
            "key = 00112233445566778899aabbccddeeff\n"
            "op = 63bfa50ee6523365ff14c1f45f88737d\n"
            "amf = 8000\n"
            "\n"
            "[network]\n"
            "mcc = 001\n"
            "mnc = 01\n"
            "apn = ims\n"
            "operator_long = VeryLongOperatorName\n"
            "operator_short = VLO\n"
            "pdu_type = ipv4v6\n"
            "slice_sst = 1\n"
            "\n"
            "[backend]\n"
            "mode = real\n"
            "\n"
            "[ran]\n"
            "gnb_address = 10.0.0.1\n"
            "gnb_port = 38412\n"
            "\n"
            "[ims]\n"
            "enabled = yes\n"
            "\n"
            "[sms]\n"
            "enabled = true\n"
            "transport = ims\n"
            "\n"
            "[logging]\n"
            "level = trace\n"
            "\n"
            "[logging.domains]\n"
            "MBIM = debug\n"
            "NAS = trace\n");
    assert(fclose(f) == 0);
}

static void test_defaults_and_finalize(void)
{
    struct ue_instance_config cfg;
    assert(ue_instance_config_set_defaults(&cfg) == 0);
    assert(!strcmp(cfg.device.manufacturer, "Quectel"));
    assert(!strcmp(cfg.network.dnn, "internet"));
    assert(cfg.sim.sim_present);
    assert(cfg.ims.enabled);
    assert(cfg.sms.enabled);
    assert(cfg.sms.transport == UE_SMS_TRANSPORT_IMS);
    assert(!cfg.use_real_backend);
    assert(ue_instance_config_validate(&cfg) == 0);

    cfg.device.imei[0] = '\0';
    cfg.sim.imsi[0] = '\0';
    cfg.sim.iccid[0] = '\0';
    assert(ue_instance_config_finalize(&cfg, 42, true) == 0);
    assert(!strcmp(cfg.device.imei, "867530900000042"));
    assert(!strcmp(cfg.sim.imsi, "001010000000042"));
    assert(!strcmp(cfg.sim.iccid, "8901001000000000042"));
}

static void test_load_file(void)
{
    char path[] = "/tmp/virtuallte-config-test-XXXXXX";
    struct ue_instance_config cfg;
    int fd;

    fd = mkstemp(path);
    assert(fd >= 0);
    close(fd);
    write_config_file(path);

    assert(ue_instance_config_set_defaults(&cfg) == 0);
    assert(ue_instance_config_load_file(&cfg, path) == 0);
    unlink(path);

    assert(!strcmp(cfg.device.manufacturer, "TestMaker"));
    assert(!strcmp(cfg.device.model, "TestModel"));
    assert(!cfg.sim.sim_present);
    assert(!strcmp(cfg.sim.opc, "63bfa50ee6523365ff14c1f45f88737d"));
    assert(!strcmp(cfg.network.mcc, "001"));
    assert(!strcmp(cfg.network.mnc, "01"));
    assert(!strcmp(cfg.network.dnn, "ims"));
    assert(!strcmp(cfg.network.operator_long, "VeryLongOperatorName"));
    assert(!strcmp(cfg.network.pdu_type, "ipv4v6"));
    assert(cfg.network.slice_sst == 1);
    assert(cfg.use_real_backend);
    assert(!strcmp(cfg.ran.gnb_address, "10.0.0.1"));
    assert(cfg.ran.gnb_port == 38412);
    assert(cfg.ims.enabled);
    assert(cfg.sms.enabled);
    assert(cfg.sms.transport == UE_SMS_TRANSPORT_IMS);
    assert(!strcmp(cfg.logging.level, "trace"));
    assert(cfg.logging.domain_count == 2);
    assert(!strcmp(cfg.logging.domain_names[0], "MBIM"));
    assert(!strcmp(cfg.logging.domain_levels[0], "debug"));
    assert(!strcmp(cfg.logging.domain_names[1], "NAS"));
    assert(!strcmp(cfg.logging.domain_levels[1], "trace"));
    assert(ue_instance_config_validate(&cfg) == 0);
}

int main(void)
{
    test_defaults_and_finalize();
    test_load_file();
    return 0;
}
