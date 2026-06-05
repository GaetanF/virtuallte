#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "common/log.h"
#include "core.h"
#include "acm/acm_worker.h"
#include "state_bridge/state_bridge.h"
#include "runtime/ue_instance_config.h"

static enum log_domain resolve_domain(const char *name)
{
    if (!strcasecmp(name, "mbim"))     return LOG_DOM_MBIM;
    if (!strcasecmp(name, "acm"))      return LOG_DOM_ACM;
    if (!strcasecmp(name, "ep0"))      return LOG_DOM_EP0;
    if (!strcasecmp(name, "core"))     return LOG_DOM_CORE;
    if (!strcasecmp(name, "engine"))   return LOG_DOM_ENGINE;
    if (!strcasecmp(name, "mm"))       return LOG_DOM_MM;
    if (!strcasecmp(name, "sm"))       return LOG_DOM_SM;
    if (!strcasecmp(name, "up"))       return LOG_DOM_UP;
    if (!strcasecmp(name, "ran"))      return LOG_DOM_RAN;
    if (!strcasecmp(name, "rrc"))      return LOG_DOM_RRC;
    if (!strcasecmp(name, "nas"))      return LOG_DOM_NAS;
    if (!strcasecmp(name, "qmi"))      return LOG_DOM_QMI;
    if (!strcasecmp(name, "sbrg") || !strcasecmp(name, "state_bridge"))
        return LOG_DOM_STATE_BR;
    if (!strcasecmp(name, "ims"))      return LOG_DOM_IMS;
    return 0;
}

static void apply_logging_config(const struct ue_logging_config *lc)
{
    int i;

    log_init();

    if (lc->level[0])
        log_set_level(LOG_LVL_OFF); /* will be overridden below */

    for (i = 0; i < lc->domain_count; i++) {
        enum log_domain dom = resolve_domain(lc->domain_names[i]);
        if (dom && lc->domain_levels[i][0]) {
            enum log_level lvl = LOG_LVL_OFF;
            const char *lv = lc->domain_levels[i];
            if (!strcasecmp(lv, "error")) lvl = LOG_LVL_ERROR;
            else if (!strcasecmp(lv, "warn"))  lvl = LOG_LVL_WARN;
            else if (!strcasecmp(lv, "info"))  lvl = LOG_LVL_INFO;
            else if (!strcasecmp(lv, "debug")) lvl = LOG_LVL_DEBUG;
            else if (!strcasecmp(lv, "trace")) lvl = LOG_LVL_TRACE;
            else if (!strcasecmp(lv, "off"))   lvl = LOG_LVL_OFF;
            log_set_domain_level(dom, lvl);
        }
    }

    /* Global level applied last, overrides unset domains */
    if (lc->level[0]) {
        enum log_level lvl = LOG_LVL_INFO;
        if (!strcasecmp(lc->level, "error")) lvl = LOG_LVL_ERROR;
        else if (!strcasecmp(lc->level, "warn"))  lvl = LOG_LVL_WARN;
        else if (!strcasecmp(lc->level, "info"))  lvl = LOG_LVL_INFO;
        else if (!strcasecmp(lc->level, "debug")) lvl = LOG_LVL_DEBUG;
        else if (!strcasecmp(lc->level, "trace")) lvl = LOG_LVL_TRACE;
        else if (!strcasecmp(lc->level, "off"))   lvl = LOG_LVL_OFF;
        log_set_level(lvl);
    }
}

int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    modem_state_init_defaults(&g_modem_state);

    struct ue_instance_config cfg;
    const char *config_path = NULL;
    int positional = 0;
    if (ue_instance_config_set_defaults(&cfg) < 0) {
        fprintf(stderr, "failed to setup UE instance defaults\n");
        return 1;
    }

    const char *device = "dummy_udc.0";
    const char *driver = "dummy_udc";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--config") && i + 1 < argc) {
            config_path = argv[++i];
            continue;
        }

        if (argv[i][0] == '-' && argv[i][1] == '-')
            continue;

        if (positional == 0)
            device = argv[i];
        else if (positional == 1)
            driver = argv[i];
        positional++;
    }

    if (!config_path)
        config_path = getenv("FAKE_MBIM_CONFIG");

    if (config_path) {
        if (ue_instance_config_load_file(&cfg, config_path) < 0) {
            fprintf(stderr, "failed to load config file: %s\n", config_path);
            return 1;
        }
    }

    if (ue_instance_config_finalize(&cfg, 1, false) < 0) {
        fprintf(stderr, "invalid UE instance config\n");
        return 1;
    }

    apply_logging_config(&cfg.logging);
    LOG_INF(CORE, "fake CDC-MBIM starting on driver=%s device=%s", driver, device);

    if (state_bridge_init_default_with_config(&cfg) < 0) {
        LOG_ERR(CORE, "failed to init state bridge");
        return 1;
    }

    int fd = usb_raw_open_dev();
    usb_raw_init_dev(fd, driver, device);

    pthread_t acm_tid;
    pthread_create(&acm_tid, NULL, acm_worker, &fd);

    LOG_INF(CORE, "fake CDC-MBIM ready on driver=%s device=%s", driver, device);

    ep0_loop(fd);

    state_bridge_shutdown_default();
    close(fd);
    return 0;
}
