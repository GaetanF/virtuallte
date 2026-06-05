/*
 * log.c - Lightweight domain-based logging.
 */
#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

static enum log_level g_global_level = LOG_LVL_INFO;
static enum log_level g_domain_levels[LOG_DOM_COUNT];

static const char *g_level_names[] = {
    "ERR", "WRN", "INF", "DBG", "TRC", "OFF"
};

static const char *g_domain_names[] = {
    "mbim", "acm", "ep0", "core", "engine",
    "mm", "sm", "up", "ran", "rrc",
    "nas", "qmi", "sbrg", "ims"
};

void log_init(void)
{
    int i;
    g_global_level = LOG_LVL_INFO;
    for (i = 0; i < LOG_DOM_COUNT; i++)
        g_domain_levels[i] = LOG_LVL_OFF; /* unset, use global */
}

void log_set_level(enum log_level level)
{
    if (level > LOG_LVL_OFF)
        level = LOG_LVL_OFF;
    g_global_level = level;
}

void log_set_domain_level(enum log_domain dom, enum log_level level)
{
    int i;
    if (level > LOG_LVL_OFF)
        level = LOG_LVL_OFF;
    for (i = 0; i < LOG_DOM_COUNT; i++) {
        if (dom & (1 << i))
            g_domain_levels[i] = level;
    }
}

enum log_level log_get_level(void)
{
    return g_global_level;
}

enum log_level log_get_domain_level(enum log_domain dom)
{
    int i;
    for (i = 0; i < LOG_DOM_COUNT; i++) {
        if (dom & (1 << i)) {
            if (g_domain_levels[i] != LOG_LVL_OFF)
                return g_domain_levels[i];
        }
    }
    return g_global_level;
}

const char *log_domain_name(enum log_domain dom)
{
    int i;
    for (i = 0; i < LOG_DOM_COUNT; i++) {
        if (dom & (1 << i))
            return g_domain_names[i];
    }
    return "???";
}

const char *log_level_name(enum log_level lvl)
{
    if (lvl <= LOG_LVL_OFF)
        return g_level_names[lvl];
    return "???";
}

void log_write(enum log_domain dom, enum log_level lvl,
               const char *fmt, ...)
{
    va_list args;
    struct timespec ts;
    struct tm tm_info;

    if (lvl > log_get_domain_level(dom))
        return;

    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);

    fprintf(stderr, "[%02d:%02d:%02d.%03ld][%s][%s] ",
            tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec,
            ts.tv_nsec / 1000000,
            log_level_name(lvl), log_domain_name(dom));

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
    fflush(stderr);
}

/* --- Legacy API --- */
static int g_usb_debug = 0;

void log_printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void log_usb_dbg(const char *fmt, ...)
{
    va_list args;
    if (!g_usb_debug)
        return;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void log_set_usb_debug(int enabled)
{
    g_usb_debug = enabled;
}

void log_load_config(const char *level_str, const char **domain_strs,
                     const enum log_domain *domain_ids, int domain_count)
{
    int i;
    static const char *level_names[] = {
        "error", "warn", "info", "debug", "trace", "off", NULL
    };
    static const enum log_level level_vals[] = {
        LOG_LVL_ERROR, LOG_LVL_WARN, LOG_LVL_INFO,
        LOG_LVL_DEBUG, LOG_LVL_TRACE, LOG_LVL_OFF
    };

    if (level_str) {
        for (i = 0; level_names[i]; i++) {
            if (!strcasecmp(level_str, level_names[i])) {
                log_set_level(level_vals[i]);
                break;
            }
        }
    }

    for (i = 0; i < domain_count; i++) {
        if (!domain_strs[i] || !domain_ids[i])
            continue;
        int j;
        for (j = 0; level_names[j]; j++) {
            if (!strcasecmp(domain_strs[i], level_names[j])) {
                log_set_domain_level(domain_ids[j], level_vals[j]);
                break;
            }
        }
    }
}
