#define _GNU_SOURCE

#include <errno.h>
#include <linux/usb/raw_gadget.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>


#include "core.h"
#include "common/utils.h"
#include "mbim_frontend/mbim_indications.h"
#include "mbim_frontend/mbim_handlers.h"
#include "mbim_frontend/mbim_protocol.h"
#include "mbim_frontend/mbim_ntb.h"
#include "mbim_frontend/mbim_vendor_qmux.h"
#include "mbim_frontend/usb_transport.h"
#include "ep0/ep0_request.h"
#include "state_bridge/state_bridge.h"
#include "ue_engine/ue_engine.h"
#include "common/log.h"

static uint8_t last_mbim_cmd[4096];
static uint32_t last_mbim_cmd_len = 0;

struct bulk_io
{
    struct usb_raw_ep_io io;
    char data[4096];
};

static uint8_t last_mbim_resp[4096];
static uint32_t last_mbim_resp_len = 0;
static bool g_pending_mbim_work_prev = false;

struct core_runtime_context {
    bool eps_enabled;
    int mbim_ep_int;
    int mbim_ep_out;
    int mbim_ep_in;
    int acm_ep_int;
    struct mbim_indications_state mbim_ind_state;
    struct mbim_vendor_qmux_state qmux_state;
    bool mbim_connect_activated;
    uint32_t mbim_connect_session_id;
    bool pending_lte_attach_status_ind;
    bool notif_pending;
    bool notif_armed;
    bool ep0_get_in_progress;
};

static struct core_runtime_context g_core_ctx = {
    .eps_enabled = false,
    .mbim_ep_int = -1,
    .mbim_ep_out = -1,
    .mbim_ep_in = -1,
    .acm_ep_int = -1,
    .mbim_connect_activated = false,
    .mbim_connect_session_id = 0,
    .pending_lte_attach_status_ind = false,
    .notif_pending = false,
    .notif_armed = false,
    .ep0_get_in_progress = false,
};

/* Raw gadget FD, set during ep0_loop for downlink data delivery */
static int g_gadget_fd = -1;

int acm_ep_out = -1;
int acm_ep_in = -1;

static const char *cid_name(uint32_t cid)
{
    switch (cid) {
    case 1:  return "DEVICE_CAPS";
    case 2:  return "SUBSCRIBER_READY_STATUS";
    case 3:  return "RADIO_STATE";
    case 9:  return "REGISTER_STATE";
    case 10: return "PACKET_SERVICE";
    case 11: return "SIGNAL_STATE";
    case 12: return "CONNECT";
    case 13: return "PROVISIONED_CONTEXTS";
    case 15: return "IP_CONFIGURATION";
    case 16: return "DEVICE_SERVICES";
    case 19: return "DEVICE_SERVICE_SUBSCRIBE_LIST";
    default: return "UNKNOWN";
    }
}

static const char *cid_name_bce(uint32_t cid)
{
    switch (cid) {
    case 1: return "MS_PROVISIONED_CONTEXT_V2";
    case 3: return "MS_LTE_ATTACH_CONFIG";
    case 4: return "MS_LTE_ATTACH_STATUS";
    default: return "UNKNOWN";
    }
}

static const char *cid_name_sms(uint32_t cid)
{
    switch (cid) {
    case 1: return "SMS_CONFIGURATION";
    case 2: return "SMS_READ";
    case 3: return "SMS_SEND";
    case 4: return "SMS_DELETE";
    case 5: return "SMS_MESSAGE_STORE_STATUS";
    default: return "UNKNOWN";
    }
}

/* Service-aware CID name: the same numeric CID means different things per
 * service UUID (e.g. 3 = RADIO_STATE on basic-connect but LTE_ATTACH_CONFIG on
 * the MS extensions service). */
static const char *cid_name_svc(const uint8_t *uuid, uint32_t cid)
{
    if (memcmp(uuid, UUID_BASIC_CONNECT_EXTENSIONS, 16) == 0)
        return cid_name_bce(cid);
    if (memcmp(uuid, UUID_SMS, 16) == 0)
        return cid_name_sms(cid);
    if (memcmp(uuid, UUID_EXT_QMUX, 16) == 0)
        return "QMUX";
    return cid_name(cid);
}

#define MBIM_RESP_QUEUE_SIZE 16

struct mbim_resp_item {
    uint8_t data[4096];
    uint32_t len;
    uint32_t id;
};

static struct mbim_resp_item mbim_resp_queue[MBIM_RESP_QUEUE_SIZE];
static int mbim_resp_head = 0;
static int mbim_resp_tail = 0;
static uint32_t g_resp_item_seq = 0;
static bool g_debug_skip_lte_attach_after_ps_attach = false;
static bool g_debug_use_static_ep0_in_buf = true;
static uint8_t g_ep0_in_debug_buf[4096];
static uint32_t g_last_ep0_get_id = 0;
static bool g_last_ep0_get_is_ps_attached = false;
static uint32_t g_last_ep0_get_len = 0;
static uint32_t g_last_notified_head_id = 0;
static bool g_last_notified_head_is_ps_attached = false;
static int g_notif_ticks_since_last = -1;

static void prepare_mbim_response(void);
static void mbim_log_resp_queue(const char *tag);

uint32_t core_debug_last_ep0_get_id(void)
{
    return g_last_ep0_get_id;
}

bool core_debug_last_ep0_get_is_ps_attached(void)
{
    return g_last_ep0_get_is_ps_attached;
}

uint32_t core_debug_last_ep0_get_len(void)
{
    return g_last_ep0_get_len;
}

bool core_debug_use_static_ep0_in_buf(void)
{
    return g_debug_use_static_ep0_in_buf;
}

static void bridge_request_register_cb(void *user)
{
    (void)user;
    state_bridge_request_register();
}

static void bridge_request_connect_cb(void *user, const char *apn)
{
    (void)user;
    state_bridge_request_connect(apn);
}

static void bridge_request_disconnect_cb(void *user)
{
    (void)user;
    state_bridge_request_disconnect();
}

static void bridge_set_radio_cb(void *user, bool on)
{
    (void)user;
    state_bridge_set_radio(on);
}

static int bridge_send_sms_ims_cb(void *user, const uint8_t *pdu, uint32_t pdu_len,
                                  uint32_t *reference)
{
    (void)user;
    return state_bridge_send_sms_ims(pdu, pdu_len, reference);
}


static void reset_qmi_ctl_sync_state(void)
{
    mbim_vendor_qmux_reset(&g_core_ctx.qmux_state);
}

static void reset_mbim_standard_indication_state(void)
{
    mbim_indications_reset(&g_core_ctx.mbim_ind_state);
    g_core_ctx.pending_lte_attach_status_ind = false;
    g_core_ctx.notif_pending = false;
    g_core_ctx.notif_armed = false;
    g_core_ctx.ep0_get_in_progress = false;
    g_pending_mbim_work_prev = false;

}

#define MBIM_HELD_QUEUE_SIZE 16

struct mbim_cmd_item {
    uint8_t data[4096];
    uint32_t len;
};

static struct mbim_cmd_item mbim_held_queue[MBIM_HELD_QUEUE_SIZE];
static int mbim_held_head = 0;
static int mbim_held_tail = 0;


static bool mbim_resp_queue_empty(void)
{
    return mbim_resp_head == mbim_resp_tail;
}

static bool mbim_resp_queue_full(void)
{
    return ((mbim_resp_tail + 1) % MBIM_RESP_QUEUE_SIZE) == mbim_resp_head;
}

static int mbim_resp_queue_count(void)
{
    return (mbim_resp_tail - mbim_resp_head + MBIM_RESP_QUEUE_SIZE) % MBIM_RESP_QUEUE_SIZE;
}

static const char *packet_service_state_name(uint32_t state)
{
    if (state == 1)
        return "attaching";
    if (state == 2)
        return "attached";
    return "other";
}

static bool mbim_is_packet_service_attached(const uint8_t *d, uint32_t len)
{
    if (!d || len < 72)
        return false;
    if (get_le32(&d[0]) != MBIM_INDICATE_STATUS_MSG)
        return false;
    if (memcmp(&d[20], UUID_BASIC_CONNECT, 16) != 0)
        return false;
    if (get_le32(&d[36]) != MBIM_CID_PACKET_SERVICE)
        return false;
    return get_le32(&d[48]) == 2;
}

static void mbim_describe_item(char *buf, size_t n, const uint8_t *d, uint32_t len);

static void mbim_log_hex(const char *tag, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    char line[3 * 16 + 1];

    if (!buf || len == 0) {
        LOG_TRC(CORE, "%s hex=<empty>", tag);
        return;
    }

    for (i = 0; i < len; i += 16) {
        uint32_t j;
        uint32_t chunk = (len - i > 16) ? 16 : (len - i);
        for (j = 0; j < chunk; j++) {
            snprintf(&line[j * 3], sizeof(line) - (j * 3), "%02x ", buf[i + j]);
        }
        line[chunk * 3] = '\0';
        LOG_TRC(CORE, "%s off=%u %s", tag, i, line);
    }
}

static void log_mbim_item_summary(const char *tag, uint32_t id, const uint8_t *d, uint32_t len, const void *ptr)
{
    char desc[256];
    mbim_describe_item(desc, sizeof(desc), d, len);
    LOG_TRC(CORE, "%s id=%u ptr=%p %s", tag, id, ptr, desc);
}

static void mbim_describe_item(char *buf, size_t n, const uint8_t *d, uint32_t len)
{
    uint32_t msg_type = (len >= 12) ? get_le32(&d[0]) : 0;
    uint32_t tid = (len >= 12) ? get_le32(&d[8]) : 0;
    uint32_t cid = (len >= 40) ? get_le32(&d[36]) : 0;
    const char *service = "na";
    const uint8_t *svc_uuid = NULL;

    if (len >= 40 && (msg_type == MBIM_COMMAND_MSG ||
                      msg_type == MBIM_COMMAND_DONE ||
                      msg_type == MBIM_INDICATE_STATUS_MSG)) {
        svc_uuid = &d[20];
        if (memcmp(svc_uuid, UUID_BASIC_CONNECT, 16) == 0)
            service = "basic";
        else if (memcmp(svc_uuid, UUID_BASIC_CONNECT_EXTENSIONS, 16) == 0)
            service = "basic_ext";
        else if (memcmp(svc_uuid, UUID_SMS, 16) == 0)
            service = "sms";
        else if (memcmp(svc_uuid, UUID_EXT_QMUX, 16) == 0)
            service = "qmux";
        else
            service = "other";
    }
#define CID_NAME (svc_uuid ? cid_name_svc(svc_uuid, cid) : cid_name(cid))

    if (len >= 72 && msg_type == MBIM_INDICATE_STATUS_MSG &&
        memcmp(&d[20], UUID_BASIC_CONNECT, 16) == 0 && cid == MBIM_CID_PACKET_SERVICE) {
        uint32_t nw_error = get_le32(&d[44]);
        uint32_t state = get_le32(&d[48]);
        uint32_t data_class = get_le32(&d[52]);
        snprintf(buf, n,
                 "type=0x%08x tid=%u cid=%u(%s) svc=%s PS state=%u(%s) data_class=0x%x nw_error=%u len=%u",
                 msg_type, tid, cid, CID_NAME, service,
                 state, packet_service_state_name(state), data_class, nw_error, len);
        return;
    }

    if (len >= 48 && msg_type == MBIM_INDICATE_STATUS_MSG &&
        memcmp(&d[20], UUID_BASIC_CONNECT_EXTENSIONS, 16) == 0 &&
        cid == MBIM_EXT_CID_LTE_ATTACH_STATUS) {
        uint32_t attach_state = get_le32(&d[44]);
        snprintf(buf, n,
                 "type=0x%08x tid=%u cid=%u(%s) svc=%s LTE_ATTACH state=%u len=%u",
                 msg_type, tid, cid, CID_NAME, service, attach_state, len);
        return;
    }

    snprintf(buf, n,
             "type=0x%08x tid=%u cid=%u(%s) svc=%s len=%u",
             msg_type, tid, cid, CID_NAME, service, len);
#undef CID_NAME
}

static void mbim_log_msg_meta(const char *tag, const uint8_t *buf, uint32_t len)
{
    if (len < 12) {
        LOG_DBG(CORE, "%s len=%u", tag, len);
        return;
    }

    uint32_t msg_type = get_le32(&buf[0]);
    uint32_t tid = get_le32(&buf[8]);

    if (len >= 40 && (msg_type == MBIM_COMMAND_MSG || msg_type == MBIM_COMMAND_DONE || msg_type == MBIM_INDICATE_STATUS_MSG)) {
        uint32_t cid = get_le32(&buf[36]);
        LOG_DBG(CORE, "%s type=0x%08x tid=%u cid=%u (%s) len=%u",
                tag, msg_type, tid, cid, cid_name(cid), len);
        return;
    }

    LOG_DBG(CORE, "%s type=0x%08x tid=%u len=%u", tag, msg_type, tid, len);
}

static void mbim_resp_enqueue(const uint8_t *data, uint32_t len, const char *source)
{
    int before;
    int after;
    uint32_t id;
    char desc[256];

    if (len == 0)
        return;

    if (mbim_resp_queue_full()) {
        LOG_ERR(CORE, "MBIM response queue full, dropping response len=%u", len);
        return;
    }

    before = mbim_resp_queue_count();

    if (mbim_is_packet_service_attached(data, len)) {
        LOG_TRC(CORE,
                "PS_ATTACHED ENQUEUE_PRE src=%s len=%u src_ptr=%p q_before=%d head_slot=%d tail_slot=%d",
                source ? source : "unknown", len, (const void *)data,
                before, mbim_resp_head, mbim_resp_tail);
    }

    memcpy(mbim_resp_queue[mbim_resp_tail].data, data, len);
    mbim_resp_queue[mbim_resp_tail].len = len;
    mbim_resp_queue[mbim_resp_tail].id = ++g_resp_item_seq;
    id = mbim_resp_queue[mbim_resp_tail].id;
    mbim_resp_tail = (mbim_resp_tail + 1) % MBIM_RESP_QUEUE_SIZE;
    after = mbim_resp_queue_count();

    mbim_describe_item(desc, sizeof(desc), data, len);
    LOG_DBG(CORE,
            "ENQUEUE id=%u src=%s %s count=%d->%d head_slot=%d tail_slot=%d",
            id, source ? source : "unknown", desc,
            before, after, mbim_resp_head, mbim_resp_tail);
    if (mbim_is_packet_service_attached(data, len)) {
        LOG_TRC(CORE,
                "PS_ATTACHED ENQUEUE_POST id=%u src=%s len=%u src_ptr=%p q=%d->%d head_slot=%d tail_slot=%d",
                id, source ? source : "unknown", len, (const void *)data,
                before, after, mbim_resp_head, mbim_resp_tail);
        LOG_DBG(CORE, "CRITICAL ATTACHED ENQUEUED id=%u len=%u queue_count=%d", id, len, after);
        log_mbim_item_summary("PS_ATTACHED ENQUEUE_SUMMARY", id, data, len, data);
        mbim_log_hex("PS_ATTACHED PAYLOAD", data, len);
    }
    mbim_log_resp_queue("ENQUEUE post");
}

static uint32_t mbim_resp_dequeue(void *out)
{
    int before;
    int after;
    uint32_t id;
    char desc[256];

    if (mbim_resp_queue_empty())
        return 0;

    before = mbim_resp_queue_count();
    uint32_t len = mbim_resp_queue[mbim_resp_head].len;
    id = mbim_resp_queue[mbim_resp_head].id;
    mbim_describe_item(desc, sizeof(desc), mbim_resp_queue[mbim_resp_head].data, len);
    log_mbim_item_summary("DEQUEUE_PRE", id, mbim_resp_queue[mbim_resp_head].data, len,
                          mbim_resp_queue[mbim_resp_head].data);
    if (mbim_is_packet_service_attached(mbim_resp_queue[mbim_resp_head].data, len))
        LOG_DBG(CORE, "CRITICAL ATTACHED DEQUEUED id=%u", id);
    memcpy(out, mbim_resp_queue[mbim_resp_head].data, len);

    mbim_resp_queue[mbim_resp_head].len = 0;
    mbim_resp_queue[mbim_resp_head].id = 0;
    mbim_resp_head = (mbim_resp_head + 1) % MBIM_RESP_QUEUE_SIZE;
    after = mbim_resp_queue_count();

    LOG_DBG(CORE,
            "DEQUEUE id=%u %s count=%d->%d head_slot=%d tail_slot=%d",
            id, desc, before, after, mbim_resp_head, mbim_resp_tail);
    log_mbim_item_summary("DEQUEUE_POST", id, (const uint8_t *)out, len, out);
    mbim_log_resp_queue("DEQUEUE post");

    return len;
}

static bool mbim_resp_pending(void)
{
    return !mbim_resp_queue_empty();
}

/*
 * Read-only synthetic dump of the response queue (head -> tail).
 * Instrumentation only: does not mutate queue state.
 */
static void mbim_log_resp_queue(const char *tag)
{
    int idx = mbim_resp_head;
    int pos = 0;

    if (mbim_resp_queue_empty()) {
        LOG_DBG(CORE, "%s: resp_queue empty count=0", tag);
        return;
    }

    while (idx != mbim_resp_tail) {
        const uint8_t *d = mbim_resp_queue[idx].data;
        uint32_t len = mbim_resp_queue[idx].len;
        uint32_t id = mbim_resp_queue[idx].id;
        char desc[256];
        mbim_describe_item(desc, sizeof(desc), d, len);

        LOG_DBG(CORE, "%s: resp_queue[%d] slot=%d id=%u %s",
                tag, pos, idx, id, desc);

        idx = (idx + 1) % MBIM_RESP_QUEUE_SIZE;
        pos++;
    }
}

/*
 * True if the response queue holds at least one command response (anything
 * other than an unsolicited INDICATE_STATUS_MSG). Used to decide whether a
 * newly arrived host COMMAND must be held: command/response ordering is only
 * preserved behind a pending command response, never behind unsolicited
 * indications. Holding a command behind indications deadlocks, because the
 * host stops draining the indications while it waits for its command's reply.
 */
static bool mbim_resp_has_command_response(void)
{
    int idx = mbim_resp_head;

    while (idx != mbim_resp_tail) {
        uint32_t len = mbim_resp_queue[idx].len;
        uint32_t msg_type = (len >= 4) ? get_le32(&mbim_resp_queue[idx].data[0]) : 0;

        if (msg_type != MBIM_INDICATE_STATUS_MSG)
            return true;

        idx = (idx + 1) % MBIM_RESP_QUEUE_SIZE;
    }

    return false;
}

static bool core_has_pending_mbim_work(void)
{
    if (mbim_resp_pending())
        return true;
    if (mbim_vendor_qmux_has_pending_indication(&g_core_ctx.qmux_state))
        return true;
    if (state_bridge_has_pending_indication())
        return true;
    if (state_bridge_has_pending_sms())
        return true;
    if (g_core_ctx.pending_lte_attach_status_ind)
        return true;
    return false;
}

static bool mbim_held_queue_empty(void)
{
    return mbim_held_head == mbim_held_tail;
}

static bool mbim_held_queue_full(void)
{
    return ((mbim_held_tail + 1) % MBIM_HELD_QUEUE_SIZE) == mbim_held_head;
}

static int mbim_held_queue_count(void)
{
    return (mbim_held_tail - mbim_held_head + MBIM_HELD_QUEUE_SIZE) % MBIM_HELD_QUEUE_SIZE;
}

__attribute__((unused)) static void mbim_log_service_uuid(const uint8_t *svc)
{
    LOG_DBG(CORE, "service UUID %02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
            svc[0], svc[1], svc[2], svc[3],
            svc[4], svc[5], svc[6], svc[7],
            svc[8], svc[9], svc[10], svc[11], svc[12], svc[13], svc[14], svc[15]);
}

static bool mbim_hold_command(const uint8_t *buf, uint32_t len)
{
    uint32_t copy_len = len;

    if (mbim_held_queue_full()) {
        LOG_ERR(CORE, "MBIM held queue full, dropping command len=%u count=%d head=%d tail=%d",
                len, mbim_held_queue_count(), mbim_held_head, mbim_held_tail);
        return false;
    }

    if (copy_len > sizeof(mbim_held_queue[0].data))
        copy_len = sizeof(mbim_held_queue[0].data);

    memcpy(mbim_held_queue[mbim_held_tail].data, buf, copy_len);
    mbim_held_queue[mbim_held_tail].len = copy_len;
    mbim_held_tail = (mbim_held_tail + 1) % MBIM_HELD_QUEUE_SIZE;

    if (copy_len >= 40) {
        uint32_t tid = get_le32(&buf[8]);
        uint32_t cid = get_le32(&buf[36]);
        LOG_TRC(CORE, "MBIM held enqueue tid=%u cid=%u (%s) count=%d head=%d tail=%d",
                tid, cid, cid_name(cid),
                mbim_held_queue_count(), mbim_held_head, mbim_held_tail);
    } else {
        LOG_TRC(CORE, "MBIM held enqueue len=%u count=%d head=%d tail=%d",
                copy_len, mbim_held_queue_count(), mbim_held_head, mbim_held_tail);
    }

    return true;
}

static bool mbim_held_dequeue(uint8_t *out, uint32_t *out_len)
{
    uint32_t len;

    if (mbim_held_queue_empty())
        return false;

    len = mbim_held_queue[mbim_held_head].len;
    memcpy(out, mbim_held_queue[mbim_held_head].data, len);

    mbim_held_queue[mbim_held_head].len = 0;
    mbim_held_head = (mbim_held_head + 1) % MBIM_HELD_QUEUE_SIZE;
    *out_len = len;

    if (len >= 40) {
        uint32_t tid = get_le32(&out[8]);
        uint32_t cid = get_le32(&out[36]);
        LOG_TRC(CORE, "MBIM held dequeue tid=%u cid=%u (%s) count=%d head=%d tail=%d",
                tid, cid, cid_name(cid),
                mbim_held_queue_count(), mbim_held_head, mbim_held_tail);
    } else {
        LOG_TRC(CORE, "MBIM held dequeue len=%u count=%d head=%d tail=%d",
                len, mbim_held_queue_count(), mbim_held_head, mbim_held_tail);
    }

    return true;
}

static void mbim_send_response_available_notification(int fd)
{
    static const uint8_t mbim_response_available[8] = {
        0xa1, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };

    if (g_core_ctx.mbim_ep_int >= 0) {
        struct bulk_io notif;
        bool has_work = core_has_pending_mbim_work();
        uint32_t head_id = 0;
        bool head_is_attached = false;
        char head_desc[256] = {0};
        if (!mbim_resp_queue_empty()) {
            uint8_t *h = mbim_resp_queue[mbim_resp_head].data;
            uint32_t hlen = mbim_resp_queue[mbim_resp_head].len;
            uint32_t hid = mbim_resp_queue[mbim_resp_head].id;
            char desc[256];
            mbim_describe_item(desc, sizeof(desc), h, hlen);
            head_id = hid;
            head_is_attached = mbim_is_packet_service_attached(h, hlen);
            memcpy(head_desc, desc, sizeof(head_desc) - 1);
            LOG_DBG(CORE,
                    "MBIM NOTIF PRE head_id=%u %s queue_count=%d armed=%s in_get=%s",
                    hid, desc, mbim_resp_queue_count(),
                    g_core_ctx.notif_armed ? "yes" : "no",
                    g_core_ctx.ep0_get_in_progress ? "yes" : "no");
            LOG_DBG(CORE,
                    "NOTIF for head id=%u %s queue_count=%d head_slot=%d tail_slot=%d",
                    hid, desc, mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail);
            if (mbim_is_packet_service_attached(h, hlen))
                LOG_DBG(CORE, "critical sequence: notify head attached(id=%u)", hid);
        } else {
            LOG_DBG(CORE,
                    "NOTIF for head id=none queue_count=%d head_slot=%d tail_slot=%d",
                    mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail);
        }
        memset(&notif, 0, sizeof(notif));
        notif.io.ep = g_core_ctx.mbim_ep_int;
        notif.io.flags = 0;
        notif.io.length = sizeof(mbim_response_available);
        memcpy(notif.data, mbim_response_available, sizeof(mbim_response_available));
        mbim_log_hex("MBIM NOTIF PAYLOAD", (const uint8_t *)notif.data, notif.io.length);
        errno = 0;
        int nr = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, &notif.io);
        LOG_DBG(CORE, "MBIM NOTIF POST head_id=%u rv=%d errno=%d len=%u",
                head_id, nr, errno, notif.io.length);
        LOG_DBG(CORE, "MBIM NOTIF write ep=%d rv=%d errno=%d queue_count=%d has_work=%s",
                g_core_ctx.mbim_ep_int, nr, errno, mbim_resp_queue_count(),
                has_work ? "yes" : "no");
        g_last_notified_head_id = head_id;
        g_last_notified_head_is_ps_attached = head_is_attached;
        g_notif_ticks_since_last = 0;
        if (head_is_attached)
            LOG_DBG(CORE, "CRITICAL ATTACHED NOTIFIED id=%u", head_id);
        if (head_is_attached)
            LOG_DBG(CORE, "CRITICAL NOTIF PACKET_SERVICE_ATTACHED head_id=%u %s", head_id, head_desc);
    } else {
        LOG_DBG(CORE, "MBIM NOTIF skipped ep=%d queue_count=%d",
                g_core_ctx.mbim_ep_int, mbim_resp_queue_count());
    }
}

static void mbim_mark_notification_needed(const char *reason)
{
    g_core_ctx.notif_pending = true;
    LOG_DBG(CORE, "MBIM NOTIF deferred reason=%s queue_count=%d armed=%s",
            reason,
            mbim_resp_queue_count(),
            g_core_ctx.notif_armed ? "yes" : "no");
}

static void mbim_try_send_deferred_notification(int fd, const char *reason)
{
    bool has_work;
    const char *decision = "return_no_pending";
    uint32_t head_id = 0;
    char head_desc[256];
    bool head_present = false;

    head_desc[0] = '\0';

    if (!mbim_resp_queue_empty()) {
        uint8_t *h = mbim_resp_queue[mbim_resp_head].data;
        uint32_t hlen = mbim_resp_queue[mbim_resp_head].len;
        head_id = mbim_resp_queue[mbim_resp_head].id;
        mbim_describe_item(head_desc, sizeof(head_desc), h, hlen);
        head_present = true;
    }

    if (fd < 0 || g_core_ctx.mbim_ep_int < 0)
        return;

    if (!g_core_ctx.notif_pending) {
        decision = "return_no_pending";
        LOG_DBG(CORE,
                "MBIM NOTIF decision=%s reason=%s resp_pending=%s notif_pending=%s armed=%s in_get=%s queue_count=%d head_slot=%d tail_slot=%d head_id=%s%s",
                decision, reason,
                mbim_resp_pending() ? "yes" : "no",
                g_core_ctx.notif_pending ? "yes" : "no",
                g_core_ctx.notif_armed ? "yes" : "no",
                g_core_ctx.ep0_get_in_progress ? "yes" : "no",
                mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail,
                head_present ? "present" : "none",
                head_present ? "" : "");
        return;
    }

    if (g_core_ctx.ep0_get_in_progress) {
        decision = "defer_in_get";
        LOG_DBG(CORE,
                "MBIM NOTIF decision=%s reason=%s resp_pending=%s notif_pending=%s armed=%s in_get=%s queue_count=%d head_slot=%d tail_slot=%d head_id=%u %s",
                decision, reason,
                mbim_resp_pending() ? "yes" : "no",
                g_core_ctx.notif_pending ? "yes" : "no",
                g_core_ctx.notif_armed ? "yes" : "no",
                g_core_ctx.ep0_get_in_progress ? "yes" : "no",
                mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail,
                head_id, head_present ? head_desc : "head=none");
        return;
    }

    if (g_core_ctx.notif_armed) {
        decision = "skip_armed";
        LOG_DBG(CORE,
                "MBIM NOTIF decision=%s reason=%s resp_pending=%s notif_pending=%s armed=%s in_get=%s queue_count=%d head_slot=%d tail_slot=%d head_id=%u %s",
                decision, reason,
                mbim_resp_pending() ? "yes" : "no",
                g_core_ctx.notif_pending ? "yes" : "no",
                g_core_ctx.notif_armed ? "yes" : "no",
                g_core_ctx.ep0_get_in_progress ? "yes" : "no",
                mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail,
                head_id, head_present ? head_desc : "head=none");
        return;
    }

    has_work = mbim_resp_pending();
    LOG_DBG(CORE,
            "MBIM NOTIF gate reason=%s resp_pending=%s queue_count=%d armed=%s in_get=%s",
            reason,
            has_work ? "yes" : "no",
            mbim_resp_queue_count(),
            g_core_ctx.notif_armed ? "yes" : "no",
            g_core_ctx.ep0_get_in_progress ? "yes" : "no");

    if (!has_work) {
        g_core_ctx.notif_pending = false;
        decision = "clear_no_work";
        LOG_DBG(CORE,
                "MBIM NOTIF decision=%s reason=%s resp_pending=%s notif_pending=%s armed=%s in_get=%s queue_count=%d head_slot=%d tail_slot=%d",
                decision, reason,
                mbim_resp_pending() ? "yes" : "no",
                g_core_ctx.notif_pending ? "yes" : "no",
                g_core_ctx.notif_armed ? "yes" : "no",
                g_core_ctx.ep0_get_in_progress ? "yes" : "no",
                mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail);
        return;
    }

    mbim_send_response_available_notification(fd);
    g_core_ctx.notif_armed = true;
    g_core_ctx.notif_pending = false;
    decision = "send";
    LOG_DBG(CORE,
            "MBIM NOTIF decision=%s reason=%s resp_pending=%s notif_pending=%s armed=%s in_get=%s queue_count=%d head_slot=%d tail_slot=%d head_id=%u %s",
            decision, reason,
            mbim_resp_pending() ? "yes" : "no",
            g_core_ctx.notif_pending ? "yes" : "no",
            g_core_ctx.notif_armed ? "yes" : "no",
            g_core_ctx.ep0_get_in_progress ? "yes" : "no",
            mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail,
            head_id, head_present ? head_desc : "head=none");
}

static void mbim_process_held_command(void)
{
    uint32_t held_len = 0;
    uint32_t s_tid;
    uint32_t s_cid;

    LOG_DBG(CORE, "process_held_command: entry held_count=%d resp_count=%d",
            mbim_held_queue_count(), mbim_resp_queue_count());

    if (!mbim_held_dequeue(last_mbim_cmd, &held_len)) {
        LOG_DBG(CORE, "process_held_command: no held command selected");
        return;
    }

    last_mbim_cmd_len = held_len;

    s_tid = (held_len >= 12) ? get_le32(&last_mbim_cmd[8]) : 0;
    s_cid = (held_len >= 40) ? get_le32(&last_mbim_cmd[36]) : 0;
    LOG_DBG(CORE, "process_held_command: selected tid=%u cid=%u (%s)",
            s_tid, s_cid, cid_name(s_cid));
    if (s_cid == 12)
        LOG_DBG(CORE, "process_held_command: CONNECT selected tid=%u", s_tid);

    LOG_DBG(CORE, "MBIM held command processed after dequeue");

    prepare_mbim_response();

    if (last_mbim_resp_len > 0) {
        mbim_resp_enqueue(last_mbim_resp, last_mbim_resp_len, "held_cmd_done");
        mbim_mark_notification_needed("held_command_response");
    }

    /*
     * Do NOT emit the doorbell here: this runs inside the GET handler, before
     * the current GET's EP0 transfer has been written. Marking it pending lets
     * the next core_ep0_tick() emit it once no EP0 transfer is in flight, so
     * the single RESPONSE_AVAILABLE that cdc_wdm tracks is not folded into the
     * GET still being read (same race as the post_get_retry path).
     */
}


static bool mbim_enqueue_indication_blob(void *user, const uint8_t *data, uint32_t len)
{
    (void)user;
    if (mbim_resp_queue_full()) {
        LOG_WRN(CORE, "standard indication dropped (response queue full)");
        return false;
    }

    mbim_resp_enqueue(data, len, "indication");
    LOG_DBG(CORE, "queued standard INDICATE_STATUS len=%u", len);
    mbim_mark_notification_needed("enqueue_indication");
    return true;
}

__attribute__((unused)) static void mbim_emit_sms_configuration_indication(int fd)
{
    mbim_indications_emit_sms_configuration(&g_core_ctx.mbim_ind_state, mbim_enqueue_indication_blob, &fd);
}

__attribute__((unused)) static void mbim_emit_packet_service_indication(int fd)
{
    mbim_indications_emit_packet_service(&g_core_ctx.mbim_ind_state, mbim_enqueue_indication_blob, &fd);
}

static void mbim_emit_packet_service_attaching_indication(int fd)
{
    mbim_indications_emit_packet_service_attaching(mbim_enqueue_indication_blob, &fd);
}

static void mbim_emit_sms_store_status_indication(int fd, uint32_t message_index)
{
    mbim_indications_emit_sms_message_store_status(mbim_enqueue_indication_blob, &fd,
                                                   message_index);
}

/*
 * Unsolicited SMS_READ indication carrying the new (unread) message(s). This is
 * the notification ModemManager acts on to fetch the inbox — SMS_MESSAGE_STORE_
 * STATUS alone does not trigger a read.
 */
static void mbim_emit_sms_read_indication(int fd)
{
    uint8_t info[512];
    uint32_t info_len = 0;

    if (mbim_handlers_build_sms_read_indication(info, sizeof(info), &info_len))
        mbim_indications_emit_sms_read(mbim_enqueue_indication_blob, &fd, info, info_len);
}

static void mbim_emit_register_state_searching_indication(int fd)
{
    mbim_indications_emit_register_state_searching(mbim_enqueue_indication_blob, &fd);
}

static void mbim_emit_register_state_home_indication(int fd)
{
    mbim_indications_emit_register_state_home(mbim_enqueue_indication_blob, &fd, &g_modem_state);
}

__attribute__((unused)) static void mbim_emit_register_state_indication(int fd)
{
    mbim_indications_emit_register_state(&g_core_ctx.mbim_ind_state, mbim_enqueue_indication_blob, &fd);
}

__attribute__((unused)) static void mbim_emit_radio_state_indication(int fd)
{
    mbim_indications_emit_radio_state(&g_core_ctx.mbim_ind_state, mbim_enqueue_indication_blob, &fd);
}

__attribute__((unused)) static void mbim_emit_connect_indication(int fd)
{
    mbim_indications_emit_connect(mbim_enqueue_indication_blob, &fd);
}

static void mbim_emit_lte_attach_status_indication(int fd)
{
    mbim_indications_emit_lte_attach_status(mbim_enqueue_indication_blob, &fd, &g_modem_state);
}

static bool mbim_enqueue_response_blob(void *user, const uint8_t *data, uint32_t len)
{
    (void)user;
    if (mbim_resp_queue_full())
        return false;
    mbim_resp_enqueue(data, len, "resp_blob");
    return true;
}

/*
 * Downlink data-plane.
 *
 * Symmetric to the uplink: the engine (main thread, via the DL callback) frames
 * each IP datagram into an NTB and queues it here; a dedicated thread owns the
 * BLOCKING EP_WRITE. Without this, a host that stops draining the bulk-IN
 * endpoint would block the main thread inside ioctl(EP_WRITE), which stalls the
 * engine tick and therefore the periodic RLS heartbeats -> the gNB declares the
 * UE "signal lost" and tears down the RAN context (UE re-appears with no PDU
 * session). Keeping the blocking write off the main thread prevents that.
 */
#define DL_FIFO_DEPTH 64

struct dl_pkt {
    uint32_t len;
    uint8_t  data[2048];   /* NTB for one MTU-1500 IP datagram (~1528B) */
};

static struct dl_pkt    g_dl_fifo[DL_FIFO_DEPTH];
static int              g_dl_head = 0;
static int              g_dl_tail = 0;
static pthread_mutex_t  g_dl_lock = PTHREAD_MUTEX_INITIALIZER;

static void dl_fifo_push(const uint8_t *data, uint32_t len)
{
    int next;

    if (len > sizeof(g_dl_fifo[0].data))
        return;

    pthread_mutex_lock(&g_dl_lock);
    next = (g_dl_tail + 1) % DL_FIFO_DEPTH;
    if (next != g_dl_head) {
        memcpy(g_dl_fifo[g_dl_tail].data, data, len);
        g_dl_fifo[g_dl_tail].len = len;
        g_dl_tail = next;
    }
    /* else: FIFO full -> drop (downlink is best-effort) */
    pthread_mutex_unlock(&g_dl_lock);
}

static uint32_t dl_fifo_pop(uint8_t *out, uint32_t cap)
{
    uint32_t len = 0;

    pthread_mutex_lock(&g_dl_lock);
    if (g_dl_head != g_dl_tail) {
        len = g_dl_fifo[g_dl_head].len;
        if (len > cap)
            len = cap;
        memcpy(out, g_dl_fifo[g_dl_head].data, len);
        g_dl_head = (g_dl_head + 1) % DL_FIFO_DEPTH;
    }
    pthread_mutex_unlock(&g_dl_lock);
    return len;
}

/* Dedicated thread: blocking-writes queued NTBs to the MBIM data IN endpoint. */
static void *mbim_dl_worker(void *arg)
{
    (void)arg;

    for (;;) {
        struct bulk_io tx;
        uint32_t n = dl_fifo_pop((uint8_t *)tx.data, sizeof(tx.data));
        int fd = g_gadget_fd;
        int ep = g_core_ctx.mbim_ep_in;
        int rv;

        if (n == 0) {
            usleep(200);          /* nothing queued */
            continue;
        }
        if (fd < 0 || ep < 0)
            continue;             /* EP not up: drop (already dequeued) */

        tx.io.ep = ep;
        tx.io.flags = 0;
        tx.io.length = (__u32)n;
        rv = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, &tx.io);
        if (rv < 0)
            usleep(1000);         /* host not draining / EP error: back off */
    }

    return NULL;
}

/*
 * Downlink data delivery: frame an IP packet into an NTB and queue it for the
 * downlink worker thread. Called from ue_up via state_bridge (main thread).
 */
static int core_mbim_dl_callback(int psi, const uint8_t *data,
                                 size_t len, void *user_data)
{
    static uint16_t dl_seq;
    uint8_t ntb[2048];
    uint32_t ntb_len;

    (void)user_data;
    (void)psi;

    if (g_gadget_fd < 0 || g_core_ctx.mbim_ep_in < 0)
        return -1;
    if (!g_core_ctx.mbim_connect_activated)
        return -1;
    if (len == 0)
        return -1;

    /* Wrap the IP datagram in an NTB16 (the host expects NCM framing). */
    ntb_len = mbim_ntb16_frame_single(ntb, sizeof(ntb),
                                      data, (uint32_t)len, dl_seq++);
    if (ntb_len == 0) {
        LOG_ERR(CORE, "MBIM DL frame failed len=%zu", len);
        return -1;
    }

    dl_fifo_push(ntb, ntb_len);   /* the DL worker does the blocking EP_WRITE */
    LOG_TRC(CORE, "MBIM DL queued ip_len=%zu ntb_len=%u", len, ntb_len);
    return 0;
}

/*
 * Convert every pending spontaneous indication (qmux deferred,
 * delayed LTE_ATTACH_STATUS, then bridge indications) into the MBIM
 * response queue. Sole owner of the source-queue -> resp-queue
 * conversion, called both proactively from the tick and opportunistically
 * from the GET handler so the two paths cannot diverge.
 *
 * Guards: held COMMANDs must be answered in order first (return early
 * while one is queued); every step bails out when the resp queue is full,
 * leaving the remainder in its source queue for the next call.
 */
static void drain_pending_indications(int fd)
{
    if (!mbim_held_queue_empty())
        return;

    if (!mbim_resp_queue_full() &&
        mbim_vendor_qmux_has_pending_indication(&g_core_ctx.qmux_state)) {
        uint8_t deferred_ind[4096];
        uint32_t deferred_ind_len;

        deferred_ind_len = mbim_vendor_qmux_take_pending_indication(&g_core_ctx.qmux_state,
                                                                    deferred_ind,
                                                                    sizeof(deferred_ind));
        if (deferred_ind_len > 0) {
            mbim_resp_enqueue(deferred_ind, deferred_ind_len, "qmux_ind");
            LOG_DBG(CORE, "drained QMI_CTL_SYNC indication len=%u queue_count=%d",
                    deferred_ind_len, mbim_resp_queue_count());
        }
        mbim_vendor_qmux_mark_indication_sent(&g_core_ctx.qmux_state);
        mbim_mark_notification_needed("drain_qmux_indication");
    }

    if (!mbim_resp_queue_full() && g_core_ctx.pending_lte_attach_status_ind) {
        LOG_DBG(CORE, "draining delayed LTE_ATTACH_STATUS indication");
        mbim_emit_lte_attach_status_indication(fd);
        g_core_ctx.pending_lte_attach_status_ind = false;
        LOG_DBG(CORE,
                "LTE_ATTACH_STATUS drained resp_pending=%s armed=%s queue_count=%d head_slot=%d tail_slot=%d",
                mbim_resp_pending() ? "yes" : "no",
                g_core_ctx.notif_armed ? "yes" : "no",
                mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail);
    }

    while (!mbim_resp_queue_full() && state_bridge_has_pending_indication()) {
        enum mbim_bridge_indication next_ind = state_bridge_next_indication();

        LOG_DBG(CORE, "draining bridge indication next_ind=%d", next_ind);

        if (next_ind == MBIM_BRIDGE_IND_REGISTER_SEARCHING) {
            mbim_emit_register_state_searching_indication(fd);
        } else if (next_ind == MBIM_BRIDGE_IND_REGISTER_DEREGISTERED) {
            mbim_indications_emit_register_state_deregistered(mbim_enqueue_indication_blob, &fd);
        } else if (next_ind == MBIM_BRIDGE_IND_REGISTER_HOME) {
            mbim_emit_register_state_home_indication(fd);
        } else if (next_ind == MBIM_BRIDGE_IND_PACKET_ATTACHING) {
            mbim_emit_packet_service_attaching_indication(fd);
        } else if (next_ind == MBIM_BRIDGE_IND_PACKET_ATTACHED) {
            bool ok = mbim_indications_emit_packet_service_attached(mbim_enqueue_indication_blob, &fd);
            LOG_DBG(CORE, "PACKET_SERVICE attached emit result=%s queue_count=%d",
                    ok ? "ok" : "fail", mbim_resp_queue_count());
            if (ok) {
                if (g_debug_skip_lte_attach_after_ps_attach) {
                    LOG_DBG(CORE, "DEBUG skip LTE_ATTACH_STATUS right after PACKET_SERVICE attached");
                } else {
                    g_core_ctx.pending_lte_attach_status_ind = true;
                    LOG_DBG(CORE, "scheduled delayed LTE_ATTACH_STATUS indication");
                    if (!mbim_resp_queue_empty()) {
                        uint32_t hid = mbim_resp_queue[mbim_resp_head].id;
                        LOG_DBG(CORE, "critical sequence: attached(id=%u) then lte_attach(pending)", hid);
                    }
                }
            } else {
                LOG_WRN(CORE, "failed to queue PACKET_SERVICE attached indication");
            }
        } else if (next_ind == MBIM_BRIDGE_IND_PACKET_DETACHED) {
            bool ok = mbim_indications_emit_packet_service_detached(mbim_enqueue_indication_blob, &fd);
            LOG_DBG(CORE, "PACKET_SERVICE detached emit result=%s queue_count=%d",
                    ok ? "ok" : "fail", mbim_resp_queue_count());
            if (ok)
                g_core_ctx.pending_lte_attach_status_ind = true;
        } else {
            break;
        }
    }

    /* Incoming SMS over IMS: store each PDU and flag new-message status. */
    bool sms_arrived = false;
    while (!mbim_resp_queue_full() && state_bridge_has_pending_sms()) {
        uint8_t pdu[512];
        size_t pdu_len = 0;
        uint32_t message_index = 0;

        if (!state_bridge_pop_sms(pdu, sizeof(pdu), &pdu_len))
            break;
        if (!mbim_handlers_sms_store_append(pdu, (uint32_t)pdu_len, &message_index)) {
            LOG_WRN(CORE, "failed to store incoming SMS len=%zu", pdu_len);
            continue;
        }
        mbim_emit_sms_store_status_indication(fd, message_index);
        sms_arrived = true;
    }
    /*
     * Then push the new message(s) to the host via an SMS_READ indication —
     * this is what makes ModemManager fetch the inbox (it does not read on
     * SMS_MESSAGE_STORE_STATUS alone).
     */
    if (sms_arrived && !mbim_resp_queue_full())
        mbim_emit_sms_read_indication(fd);
}

/*
 * Uplink data-plane.
 *
 * raw-gadget endpoint I/O is BLOCKING (USB_RAW_IOCTL_EP_READ waits for transfer
 * completion; O_NONBLOCK only affects EVENT_FETCH), so a dedicated thread owns
 * the blocking read of the MBIM data OUT endpoint. It deframes the NTB and
 * injects each IP datagram straight into the engine uplink path (the RAN send
 * path is thread-safe), instead of handing off to the EP0 tick — which can
 * stall for hundreds of ms when EVENT_FETCH blocks.
 */
static void ul_deframe_cb(void *user, const uint8_t *dg, uint32_t dg_len)
{
    struct ue_engine *engine;

    (void)user;

    /*
     * Inject the uplink IP datagram straight from this data-plane worker thread.
     * The engine RAN send path is now thread-safe (per-call tx buffers + the
     * cell-table lock), so uplink no longer waits for the EP0 tick to drain a
     * FIFO — which could stall for hundreds of ms when EVENT_FETCH blocks.
     */
    if (!g_core_ctx.mbim_connect_activated)
        return;
    engine = state_bridge_default_engine();
    if (engine)
        ue_engine_inject_uplink_ip(engine, dg, dg_len);
}

/* Dedicated thread: blocking-reads the MBIM data OUT endpoint, deframes the
 * NTB16 into IP datagrams and injects them into the engine uplink path. */
static void *mbim_data_worker(void *arg)
{
    (void)arg;

    for (;;) {
        struct bulk_io rx;
        int fd = g_gadget_fd;
        int ep = g_core_ctx.mbim_ep_out;
        int rv;

        if (fd < 0 || ep < 0) {
            usleep(10000);   /* data EP not up yet */
            continue;
        }

        memset(&rx, 0, sizeof(rx));
        rx.io.ep = ep;
        rx.io.flags = 0;
        rx.io.length = sizeof(rx.data);

        rv = ioctl(fd, USB_RAW_IOCTL_EP_READ, &rx.io);
        if (rv > 0)
            mbim_ntb16_deframe((const uint8_t *)rx.data, (uint32_t)rv,
                               ul_deframe_cb, NULL);
        else if (rv < 0)
            usleep(5000);    /* EP disabled / reset / error: back off */
    }

    return NULL;
}

static void core_start_data_worker(void)
{
    pthread_t tid;

    if (pthread_create(&tid, NULL, mbim_data_worker, NULL) != 0)
        LOG_ERR(CORE, "failed to start MBIM uplink data-plane worker thread");
    else
        LOG_INF(CORE, "MBIM uplink data-plane worker thread started");

    if (pthread_create(&tid, NULL, mbim_dl_worker, NULL) != 0)
        LOG_ERR(CORE, "failed to start MBIM downlink data-plane worker thread");
    else
        LOG_INF(CORE, "MBIM downlink data-plane worker thread started");
}

static void core_ep0_tick(void *user)
{
    (void)user;

    if (g_notif_ticks_since_last >= 0)
        g_notif_ticks_since_last++;
    if (g_last_notified_head_is_ps_attached && g_notif_ticks_since_last == 50) {
        LOG_WRN(CORE, "WARN no_followup_get_after_notif head_id=%u ticks=%d",
                g_last_notified_head_id, g_notif_ticks_since_last);
    }

    /*
     * Uplink is now injected directly from the data-plane worker thread
     * (ul_deframe_cb) and downlink is delivered from the RLS receive thread, so
     * neither rides this tick anymore. The engine control-plane tick still runs
     * here via state_bridge_poll().
     */
    state_bridge_poll();
    g_core_ctx.mbim_connect_activated = g_modem_state.connect_activated;
    g_core_ctx.mbim_connect_session_id = g_modem_state.connect_session_id;

    bool pending_work = core_has_pending_mbim_work();
    if (pending_work && !g_pending_mbim_work_prev) {
        LOG_DBG(CORE,
                "pending MBIM work became true resp_pending=%s qmux_pending=%s bridge_pending=%s lte_pending=%s",
                mbim_resp_pending() ? "yes" : "no",
                mbim_vendor_qmux_has_pending_indication(&g_core_ctx.qmux_state) ? "yes" : "no",
                state_bridge_has_pending_indication() ? "yes" : "no",
                g_core_ctx.pending_lte_attach_status_ind ? "yes" : "no");
    }
    g_pending_mbim_work_prev = pending_work;

    if (g_gadget_fd >= 0) {
        drain_pending_indications(g_gadget_fd);
        if (!mbim_resp_queue_empty() &&
            mbim_is_packet_service_attached(mbim_resp_queue[mbim_resp_head].data,
                                            mbim_resp_queue[mbim_resp_head].len)) {
            LOG_DBG(CORE, "CRITICAL ATTACHED HEAD id=%u queue_count=%d",
                    mbim_resp_queue[mbim_resp_head].id,
                    mbim_resp_queue_count());
        }
        if (mbim_resp_pending()) {
            mbim_mark_notification_needed("ep0_tick");
            mbim_try_send_deferred_notification(g_gadget_fd, "ep0_tick");
        }
    }
}

static enum ep0_result core_on_send_encapsulated_command(int fd,
                                                          struct usb_raw_control_io *io,
                                                          uint16_t w_length,
                                                          void *user)
{
    uint32_t msg_type = 0;
    (void)user;

    LOG_DBG(CORE, "EP0 SEND_ENCAPSULATED_COMMAND len=%u", w_length);

    /*
     * w_length is host-controlled (up to 65535). io->data and last_mbim_cmd are
     * both 4096; cap the EP0 read and the copy so a large wLength cannot overflow
     * either buffer. (sizeof(io->data) == sizeof(last_mbim_cmd).)
     */
    uint32_t copy_len = w_length;
    if (copy_len > sizeof(io->data)) {
        LOG_WRN(CORE, "SEND_ENCAPSULATED wLength=%u > %zu, truncating",
                w_length, sizeof(io->data));
        copy_len = sizeof(io->data);
    }
    if (copy_len > sizeof(last_mbim_cmd))
        copy_len = sizeof(last_mbim_cmd);

    io->inner.length = copy_len;
    usb_transport_ep0_read(fd, io);
    LOG_DBG(CORE, "USB SEND_ENCAPS read_complete bytes=%u buf_ptr=%p",
            copy_len, (void *)io->data);

    last_mbim_cmd_len = copy_len;
    memcpy(last_mbim_cmd, io->data, last_mbim_cmd_len);

    LOG_TRC(CORE, "MBIM CMD (%u bytes):", last_mbim_cmd_len);

    if (last_mbim_cmd_len >= 4)
        msg_type = get_le32(&last_mbim_cmd[0]);

    LOG_TRC(CORE, "MBIM queue pending=%s resp_count=%d held_count=%d",
            mbim_resp_pending() ? "true" : "false",
            mbim_resp_queue_count(),
            mbim_held_queue_count());

    /*
     * Only hold a new host COMMAND when a previous command response is still
     * queued (preserve command/response ordering). Do NOT hold merely because
     * unsolicited indications are pending: the command is processed now and its
     * COMMAND_DONE is enqueued behind the indications, which the host drains and
     * correlates by TID. Holding behind indications deadlocks (RouterOS stops
     * draining indications while waiting for its command reply).
     */
    if (msg_type == MBIM_COMMAND_MSG && mbim_resp_has_command_response()) {
        uint32_t h_tid = (last_mbim_cmd_len >= 12) ? get_le32(&last_mbim_cmd[8]) : 0;
        uint32_t h_cid = (last_mbim_cmd_len >= 40) ? get_le32(&last_mbim_cmd[36]) : 0;

        LOG_DBG(CORE, "HOLD command tid=%u cid=%u (%s) resp_count=%d held_count=%d (command response pending)",
                h_tid, h_cid, cid_name(h_cid),
                mbim_resp_queue_count(), mbim_held_queue_count());
        mbim_log_resp_queue("HOLD snapshot");

        if (mbim_hold_command(last_mbim_cmd, last_mbim_cmd_len))
            LOG_WRN(CORE, "MBIM command held tid=%u resp_count=%d held_count=%d",
                    get_le32(&last_mbim_cmd[8]), mbim_resp_queue_count(), mbim_held_queue_count());
        return EP0_CONSUMED_REQ;
    }

    prepare_mbim_response();

    if (last_mbim_resp_len > 0) {
        LOG_DBG(CORE,
                "USB SEND_ENCAPS prepared_response resp_ptr=%p resp_len=%u host_wLength=%u",
                (void *)last_mbim_resp, last_mbim_resp_len, w_length);
        LOG_TRC(CORE, "MBIM RESP CHECK msg_len=%u info_len=%u resp_len=%u",
                get_le32(&last_mbim_resp[4]),
                get_le32(&last_mbim_resp[44]),
                last_mbim_resp_len);
        mbim_resp_enqueue(last_mbim_resp, last_mbim_resp_len, "cmd_done");
        mbim_mark_notification_needed("send_encapsulated_command_response");
    } else {
        LOG_DBG(CORE, "USB SEND_ENCAPS prepared_response none host_wLength=%u", w_length);
    }

    mbim_try_send_deferred_notification(fd, "send_encapsulated_command");

    return EP0_CONSUMED_REQ;
}

static enum ep0_result core_on_get_encapsulated_response(int fd,
                                                          struct usb_raw_control_io *io,
                                                          uint16_t w_length,
                                                          void *user)
{
    uint32_t resp_len;
    int resp_after;
    bool held_first_possible;
    uint32_t head_id = 0;
    char head_desc[256];
    uint8_t deq_copy[4096];
    uint32_t dequeued_id = 0;
    bool critical_head = false;
    uint8_t *ep0_dst = (uint8_t *)io->data;
    (void)user;

    head_desc[0] = '\0';

    if (!mbim_resp_queue_empty()) {
        head_id = mbim_resp_queue[mbim_resp_head].id;
        mbim_describe_item(head_desc, sizeof(head_desc),
                           mbim_resp_queue[mbim_resp_head].data,
                           mbim_resp_queue[mbim_resp_head].len);
        LOG_DBG(CORE, "USB GET_ENCAPS bound_to_queue head_id=%u %s", head_id, head_desc);
        critical_head = mbim_is_packet_service_attached(mbim_resp_queue[mbim_resp_head].data,
                                                         mbim_resp_queue[mbim_resp_head].len);
        if (critical_head) {
            LOG_DBG(CORE, "USB GET_ENCAPS critical_head id=%u PACKET_SERVICE attached", head_id);
            log_mbim_item_summary("USB GET_ENCAPS critical_head_summary",
                                  head_id,
                                  mbim_resp_queue[mbim_resp_head].data,
                                  mbim_resp_queue[mbim_resp_head].len,
                                  mbim_resp_queue[mbim_resp_head].data);
        }
    } else {
        LOG_WRN(CORE, "USB GET_ENCAPS no_queue_item host_wLength=%u", w_length);
    }

    LOG_DBG(CORE,
            "USB GET_ENCAPS enter host_wLength=%u resp_count=%d head_slot=%d tail_slot=%d head_id=%u",
            w_length, mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail, head_id);
    LOG_DBG(CORE,
            "GET_ENCAPS AFTER NOTIF last_notified_id=%u current_head_id=%u",
            g_last_notified_head_id, head_id);
    g_notif_ticks_since_last = -1;

    /* --- instrumentation: state at GET entry, before dequeue --- */
    resp_after = mbim_resp_queue_count() > 0 ? mbim_resp_queue_count() - 1 : 0;
    held_first_possible = (resp_after == 0) && !mbim_held_queue_empty();
    LOG_DBG(CORE,
            "GET entry: resp_count=%d held_count=%d resp_empty=%s held_empty=%s held_first_possible=%s armed=%s in_get=%s head_slot=%d tail_slot=%d head_id=%u %s (resp_after_dequeue=%d)",
            mbim_resp_queue_count(), mbim_held_queue_count(),
            mbim_resp_queue_empty() ? "yes" : "no",
            mbim_held_queue_empty() ? "yes" : "no",
            held_first_possible ? "yes" : "no",
            g_core_ctx.notif_armed ? "yes" : "no",
            g_core_ctx.ep0_get_in_progress ? "yes" : "no",
            mbim_resp_head,
            mbim_resp_tail,
            head_id,
            mbim_resp_queue_empty() ? "head=none" : head_desc,
            resp_after);
    if (!mbim_resp_queue_empty())
        mbim_log_msg_meta("GET entry head", mbim_resp_queue[mbim_resp_head].data,
                          mbim_resp_queue[mbim_resp_head].len);
    if (!mbim_resp_queue_empty())
        LOG_DBG(CORE, "USB GET_ENCAPS dequeue_about_to_happen id=%u",
                mbim_resp_queue[mbim_resp_head].id);
    if (!mbim_resp_queue_empty())
        dequeued_id = mbim_resp_queue[mbim_resp_head].id;
    mbim_log_resp_queue("GET entry");

    resp_len = mbim_resp_dequeue(deq_copy);
    LOG_DBG(CORE, "USB GET_ENCAPS dequeue_done id=%u bytes=%u tmp_ptr=%p",
            dequeued_id, resp_len, (void *)deq_copy);
    log_mbim_item_summary("USB GET_ENCAPS dequeued_item", dequeued_id, deq_copy, resp_len, deq_copy);

    if (g_debug_use_static_ep0_in_buf) {
        ep0_dst = g_ep0_in_debug_buf;
        LOG_TRC(CORE,
                "USB GET_ENCAPS debug_static_buf enabled buf_ptr=%p head_id=%u send_len=%u",
                (void *)g_ep0_in_debug_buf, dequeued_id, resp_len);
    }

    LOG_TRC(CORE, "USB GET_ENCAPS copy_pre id=%u src_ptr=%p dst_ptr=%p len=%u",
            dequeued_id, (void *)deq_copy, (void *)ep0_dst, resp_len);
    if (resp_len > sizeof(deq_copy))
        resp_len = sizeof(deq_copy);
    memcpy(ep0_dst, deq_copy, resp_len);
    if (g_debug_use_static_ep0_in_buf)
        memcpy(io->data, g_ep0_in_debug_buf, resp_len);
    LOG_TRC(CORE, "USB GET_ENCAPS copy_done id=%u dst_ptr=%p len=%u",
            dequeued_id, (void *)ep0_dst, resp_len);
    mbim_log_hex("USB GET_ENCAPS copied_payload", ep0_dst, resp_len);
    if (critical_head)
        LOG_DBG(CORE, "USB GET_ENCAPS critical_copy_done id=%u len=%u", dequeued_id, resp_len);

    g_last_ep0_get_id = dequeued_id;
    g_last_ep0_get_len = resp_len;
    g_last_ep0_get_is_ps_attached = mbim_is_packet_service_attached(ep0_dst, resp_len);
    if (g_debug_use_static_ep0_in_buf)
        LOG_TRC(CORE, "USB GET_ENCAPS final_buf source=static ptr=%p len=%u", (void *)g_ep0_in_debug_buf, resp_len);
    else
        LOG_TRC(CORE, "USB GET_ENCAPS final_buf source=stack ptr=%p len=%u", (void *)io->data, resp_len);

    g_core_ctx.ep0_get_in_progress = true;

    LOG_TRC(CORE, "EP0 GET_ENCAPSULATED_RESPONSE dequeue len=%u", resp_len);
    if (g_core_ctx.notif_armed) {
        g_core_ctx.notif_armed = false;
        LOG_DBG(CORE, "MBIM GET consumed notif resp_len=%u queue_count=%d armed=no",
                resp_len, mbim_resp_queue_count());
    }

    LOG_DBG(CORE, "EP0 GET_ENCAPSULATED_RESPONSE len=%u resp_len=%u", w_length, resp_len);
    if (resp_len > w_length) {
        LOG_WRN(CORE,
                "USB GET_ENCAPS length_mismatch resp_len=%u host_wLength=%u (clamp in dispatch)",
                resp_len, w_length);
    } else if (resp_len == 0) {
        LOG_WRN(CORE, "USB GET_ENCAPS selected empty response host_wLength=%u", w_length);
    } else {
        LOG_DBG(CORE, "USB GET_ENCAPS copy_done bytes=%u host_wLength=%u", resp_len, w_length);
    }

    LOG_TRC(CORE, "MBIM queue after dequeue pending=%s resp_count=%d held_count=%d",
            mbim_resp_pending() ? "true" : "false",
            mbim_resp_queue_count(),
            mbim_held_queue_count());
    mbim_log_resp_queue("GET after dequeue");

    /* Held COMMANDs must be answered before spontaneous indications. */
    if (mbim_resp_queue_empty() && !mbim_held_queue_empty()) {
        LOG_DBG(CORE, "GET held-first: TRIGGERS (resp_queue empty, held_count=%d)",
                mbim_held_queue_count());
        LOG_DBG(CORE, "GET_ENCAPS_RESPONSE action=process_held_first");
        mbim_process_held_command();
    } else {
        LOG_DBG(CORE, "GET held-first: skipped resp_empty=%s held_empty=%s",
                mbim_resp_queue_empty() ? "yes" : "no",
                mbim_held_queue_empty() ? "yes" : "no");
    }

    /* Convert any pending indications (no-op while a held COMMAND remains). */
    drain_pending_indications(fd);

    g_core_ctx.ep0_get_in_progress = false;

    LOG_DBG(CORE, "GET exit: resp_pending=%s queue_count=%d armed=%s in_get=%s",
            mbim_resp_pending() ? "yes" : "no",
            mbim_resp_queue_count(),
            g_core_ctx.notif_armed ? "yes" : "no",
            g_core_ctx.ep0_get_in_progress ? "yes" : "no");

    /*
     * If this GET drained one response but others remain queued (e.g.
     * PACKET_SERVICE attached then LTE_ATTACH_STATUS), only MARK the follow-up
     * ResponseAvailable as pending here -- it must NOT be emitted from inside
     * the GET handler.
     *
     * This handler returns to ep0_dispatch_loop(), which only THEN writes the
     * current GET's data/status stages on EP0 (usb_transport_ep0_write). If we
     * fired the interrupt-EP doorbell now, it would race ahead of the in-flight
     * EP0 control transfer. cdc_wdm/cdc_mbim hold a *single* RESPONSE_AVAILABLE:
     * a notification that arrives while a GET response is still outstanding is
     * folded into the one being read, so the host never issues a follow-up GET
     * and the queued message (PACKET_SERVICE attached, then everything behind
     * it) is stranded forever.
     *
     * Leaving it pending lets the next core_ep0_tick() emit it -- by then this
     * GET has fully completed and no EP0 transfer is in flight, so the host
     * receives a clean doorbell and issues the next GET.
     */
    if (mbim_resp_pending()) {
        uint32_t retry_head_id = mbim_resp_queue[mbim_resp_head].id;
        char retry_desc[256];
        mbim_describe_item(retry_desc, sizeof(retry_desc),
                           mbim_resp_queue[mbim_resp_head].data,
                           mbim_resp_queue[mbim_resp_head].len);
        LOG_DBG(CORE,
                "GET exit retry=triggered head_id=%u %s queue_count=%d head_slot=%d tail_slot=%d",
                retry_head_id, retry_desc, mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail);
        if (mbim_is_packet_service_attached(mbim_resp_queue[mbim_resp_head].data,
                                            mbim_resp_queue[mbim_resp_head].len)) {
            LOG_DBG(CORE, "USB GET_ENCAPS critical_complete id=%u status=queued_for_next_get", retry_head_id);
        }
        mbim_mark_notification_needed("post_get_retry");
        /* Do NOT emit here: the next core_ep0_tick() sends it once this GET's
         * EP0 transfer has fully completed (see comment above). */
    } else {
        LOG_DBG(CORE,
                "GET exit retry=none queue_count=%d head_slot=%d tail_slot=%d",
                mbim_resp_queue_count(), mbim_resp_head, mbim_resp_tail);
    }

    LOG_DBG(CORE,
            "USB GET_ENCAPS select host_wLength=%u send_len=%u buf_ptr=%p complete=status_ready",
            w_length, resp_len, (void *)io->data);
    if (g_last_ep0_get_is_ps_attached)
        LOG_TRC(CORE, "CRITICAL ATTACHED XFER_PREP id=%u buf_ptr=%p len=%u",
                g_last_ep0_get_id,
                g_debug_use_static_ep0_in_buf ? (void *)g_ep0_in_debug_buf : (void *)io->data,
                g_last_ep0_get_len);
    if (g_last_ep0_get_is_ps_attached)
        LOG_DBG(CORE, "USB GET_ENCAPS critical_complete id=%u status=ready_for_ep0_write", g_last_ep0_get_id);
    if (resp_len == 0)
        LOG_WRN(CORE, "USB GET_ENCAPS decision=short_or_empty reason=resp_len_zero");

    io->inner.length = resp_len;
    return EP0_REPLY_REQ;
}

static void prepare_mbim_response(void)
{
    if (last_mbim_cmd_len < 12)
        return;

    uint32_t msg_type = get_le32(&last_mbim_cmd[0]);
    uint32_t msg_len = get_le32(&last_mbim_cmd[4]);
    uint32_t tid = get_le32(&last_mbim_cmd[8]);

    LOG_DBG(CORE, "MBIM type=0x%08x len=%u tid=%u", msg_type, msg_len, tid);

    last_mbim_resp_len = 0;

    if (msg_type == MBIM_OPEN_MSG)
    {
        reset_qmi_ctl_sync_state();
        put_le32(&last_mbim_resp[0], MBIM_OPEN_DONE);
        put_le32(&last_mbim_resp[4], 16);
        put_le32(&last_mbim_resp[8], tid);
        put_le32(&last_mbim_resp[12], MBIM_STATUS_SUCCESS);
        last_mbim_resp_len = 16;

        LOG_INF(CORE, "MBIM_OPEN_DONE tid=%u", tid);
    } else if (msg_type == MBIM_CLOSE_MSG) {
        reset_qmi_ctl_sync_state();
        reset_mbim_standard_indication_state();

        put_le32(&last_mbim_resp[0], MBIM_CLOSE_DONE);
        put_le32(&last_mbim_resp[4], 16);
        put_le32(&last_mbim_resp[8], tid);
        put_le32(&last_mbim_resp[12], MBIM_STATUS_SUCCESS);
        last_mbim_resp_len = 16;

        LOG_INF(CORE, "MBIM_CLOSE_DONE tid=%u", tid);
    }else if (msg_type == MBIM_COMMAND_MSG) {
        struct mbim_handler_actions actions = {
            .request_register = bridge_request_register_cb,
            .request_connect = bridge_request_connect_cb,
            .request_disconnect = bridge_request_disconnect_cb,
            .set_radio = bridge_set_radio_cb,
            .send_sms_ims = bridge_send_sms_ims_cb,
            .sms_enabled = state_bridge_sms_enabled(),
            .ims_enabled = state_bridge_ims_enabled(),
            .ims_registered = state_bridge_ims_registered(),
            .user = NULL,
        };
        struct mbim_vendor_event vendor_event = {0};

        /* The MBIM command header (cid/cmd_type/ib_len) spans bytes [0..47];
         * the InformationBuffer starts at [48]. Reject a truncated command
         * before reading those offsets. */
        if (last_mbim_cmd_len < 48) {
            LOG_WRN(CORE, "MBIM COMMAND too short len=%u", last_mbim_cmd_len);
            last_mbim_resp_len = 0;
            return;
        }

        uint32_t tid = get_le32(&last_mbim_cmd[8]);
        uint32_t cid = get_le32(&last_mbim_cmd[36]);
        uint32_t cmd_type = get_le32(&last_mbim_cmd[40]);
        uint32_t ib_len = get_le32(&last_mbim_cmd[44]);
        uint32_t ib_off = (last_mbim_cmd_len >= 52) ? get_le32(&last_mbim_cmd[48]) : 0;

        LOG_DBG(CORE, "MBIM COMMAND tid=%u cid=%u (%s) cmd_type=%u ib_len=%u ib_off=%u",
                tid, cid, cid_name(cid), cmd_type, ib_len, ib_off);

        if (!mbim_handlers_handle_command(last_mbim_cmd,
                                          last_mbim_cmd_len,
                                          &g_modem_state,
                                          &actions,
                                          last_mbim_resp,
                                          &last_mbim_resp_len,
                                          &vendor_event)) {
            last_mbim_resp_len = 0;
            return;
        }

        if (vendor_event.type == MBIM_VENDOR_EVENT_QMI_CTL_SYNC) {
            if (mbim_vendor_qmux_handle_ctl_sync(&g_core_ctx.qmux_state,
                                                 vendor_event.tid,
                                                 vendor_event.cid,
                                                 &last_mbim_cmd[20],
                                                 vendor_event.qmi_payload,
                                                 vendor_event.qmi_payload_len,
                                                 mbim_enqueue_response_blob,
                                                 NULL)) {
                LOG_DBG(CORE, "queued QMI_CTL_SYNC COMMAND_DONE queue_count=%d", mbim_resp_queue_count());
                mbim_mark_notification_needed("qmi_ctl_sync_command_done");
                mbim_try_send_deferred_notification(g_gadget_fd, "qmi_ctl_sync_command_done");
            }
            return;
        }

        LOG_DBG(CORE, "COMMAND_DONE tid=%u cid=%u (%s) resp_len=%u",
                tid, cid, cid_name(cid), last_mbim_resp_len);
    }
}

void ep0_loop(int fd)
{
    g_gadget_fd = fd;

    /* Wire downlink data delivery: ue_up → state_bridge → MBIM data EP */
    state_bridge_set_downlink_callback(core_mbim_dl_callback, NULL);

    /* Uplink data path runs on its own thread (blocking EP read must not stall
     * this control loop). */
    core_start_data_worker();

    struct ep0_request_context req_ctx = {
        .eps_enabled = &g_core_ctx.eps_enabled,
        .mbim_ep_int = &g_core_ctx.mbim_ep_int,
        .mbim_ep_out = &g_core_ctx.mbim_ep_out,
        .mbim_ep_in = &g_core_ctx.mbim_ep_in,
        .acm_ep_int = &g_core_ctx.acm_ep_int,
        .acm_ep_out = &acm_ep_out,
        .acm_ep_in = &acm_ep_in,
        .on_send_encapsulated_command = core_on_send_encapsulated_command,
        .on_get_encapsulated_response = core_on_get_encapsulated_response,
        .user = NULL,
    };

    ep0_dispatch_loop(fd, ep0_handle_request, core_ep0_tick, &req_ctx);
}
