#ifndef MBIM_HANDLERS_H
#define MBIM_HANDLERS_H

#include <stdbool.h>
#include <stdint.h>

struct modem_state;

struct mbim_handler_actions {
    void (*request_register)(void *user);
    void (*request_connect)(void *user, const char *apn);
    void (*request_disconnect)(void *user);
    void (*set_radio)(void *user, bool on);
    /* SMS over IMS (IMS-only). Returns 0 on success and fills *reference. */
    int (*send_sms_ims)(void *user, const uint8_t *pdu, uint32_t pdu_len,
                        uint32_t *reference);
    bool sms_enabled;
    bool ims_enabled;
    bool ims_registered;
    void *user;
};

enum mbim_vendor_event_type {
    MBIM_VENDOR_EVENT_NONE = 0,
    MBIM_VENDOR_EVENT_QMI_CTL_SYNC,
};

struct mbim_vendor_event {
    enum mbim_vendor_event_type type;
    uint32_t tid;
    uint32_t cid;
    const uint8_t *qmi_payload;
    uint32_t qmi_payload_len;
};

bool mbim_handlers_handle_command(const uint8_t *cmd,
                                  uint32_t cmd_len,
                                  struct modem_state *state,
                                  const struct mbim_handler_actions *actions,
                                  uint8_t *resp,
                                  uint32_t *resp_len,
                                  struct mbim_vendor_event *vendor_event);

/* Internal SMS store: incoming SMS PDUs delivered to the host via SMS_READ. */
bool mbim_handlers_sms_store_append(const uint8_t *pdu, uint32_t pdu_len,
                                    uint32_t *message_index);
bool mbim_handlers_sms_store_has_unread(uint32_t *message_index);

/* Build an MBIM_SMS_READ_INFO with the unread (new) messages for an unsolicited
 * SMS_READ indication (marks them read). Returns true if >=1 message included. */
bool mbim_handlers_build_sms_read_indication(uint8_t *out, uint32_t out_cap,
                                             uint32_t *out_len);

#endif
