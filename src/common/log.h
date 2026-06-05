#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

/*
 * Lightweight domain-based logging for fake_mbim.
 *
 * Levels: error < warn < info < debug < trace
 * Domains: bitmask-based for efficient filtering.
 *
 * Usage:
 *   LOG_INFO(MBIM, "command tid=%u cid=%u", tid, cid);
 *   LOG_DBG(NAS, "decode %02x len=%zu", msg_type, len);
 *   LOG_ERR(RAN, "sendto failed errno=%d", errno);
 */

/* --- Log levels --- */
enum log_level {
    LOG_LVL_ERROR = 0,
    LOG_LVL_WARN  = 1,
    LOG_LVL_INFO  = 2,
    LOG_LVL_DEBUG = 3,
    LOG_LVL_TRACE = 4,
    LOG_LVL_OFF   = 5,
};

/* --- Log domains (bitmask) --- */
enum log_domain {
    LOG_DOM_MBIM        = (1 << 0),
    LOG_DOM_ACM         = (1 << 1),
    LOG_DOM_EP0         = (1 << 2),
    LOG_DOM_CORE        = (1 << 3),
    LOG_DOM_ENGINE      = (1 << 4),
    LOG_DOM_MM          = (1 << 5),
    LOG_DOM_SM          = (1 << 6),
    LOG_DOM_UP          = (1 << 7),
    LOG_DOM_RAN         = (1 << 8),
    LOG_DOM_RRC         = (1 << 9),
    LOG_DOM_NAS         = (1 << 10),
    LOG_DOM_QMI         = (1 << 11),
    LOG_DOM_STATE_BR    = (1 << 12),
    LOG_DOM_IMS         = (1 << 13),
    LOG_DOM_COUNT       = 14,
    LOG_DOM_ALL         = 0x3FFF,
};

/* --- Init / config --- */
void log_init(void);
void log_set_level(enum log_level level);
void log_set_domain_level(enum log_domain dom, enum log_level level);
enum log_level log_get_level(void);
enum log_level log_get_domain_level(enum log_domain dom);
void log_load_config(const char *level_str, const char **domain_strs,
                     const enum log_domain *domain_ids, int domain_count);

/* --- Core log function --- */
void log_write(enum log_domain dom, enum log_level lvl,
               const char *fmt, ...);

/* --- Legacy API (kept for compat) --- */
void log_printf(const char *fmt, ...);
void log_usb_dbg(const char *fmt, ...);
void log_set_usb_debug(int enabled);

/* --- Domain name for output --- */
const char *log_domain_name(enum log_domain dom);
const char *log_level_name(enum log_level lvl);

/* --- Macros --- */
#define LOG_ERR(dom, fmt, ...) \
    log_write(dom, LOG_LVL_ERROR, fmt, ##__VA_ARGS__)
#define LOG_WRN(dom, fmt, ...) \
    log_write(dom, LOG_LVL_WARN, fmt, ##__VA_ARGS__)
#define LOG_INF(dom, fmt, ...) \
    log_write(dom, LOG_LVL_INFO, fmt, ##__VA_ARGS__)
#define LOG_DBG(dom, fmt, ...) \
    log_write(dom, LOG_LVL_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_TRC(dom, fmt, ...) \
    log_write(dom, LOG_LVL_TRACE, fmt, ##__VA_ARGS__)

/* Shorthand domain aliases for macro use */
#define MBIM    LOG_DOM_MBIM
#define ACM     LOG_DOM_ACM
#define EP0     LOG_DOM_EP0
#define CORE    LOG_DOM_CORE
#define ENGINE  LOG_DOM_ENGINE
#define MM      LOG_DOM_MM
#define SM      LOG_DOM_SM
#define UP      LOG_DOM_UP
#define RAN     LOG_DOM_RAN
#define RRC     LOG_DOM_RRC
#define NAS     LOG_DOM_NAS
#define QMI     LOG_DOM_QMI
#define SBRG    LOG_DOM_STATE_BR
#define IMS     LOG_DOM_IMS

#endif
