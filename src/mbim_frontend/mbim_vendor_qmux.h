#ifndef MBIM_VENDOR_QMUX_H
#define MBIM_VENDOR_QMUX_H

#include <stdbool.h>
#include <stdint.h>

struct mbim_vendor_qmux_state {
    bool sync_ind_sent;
    bool sync_ind_pending;
    uint8_t sync_ind_buf[4096];
    uint32_t sync_ind_len;
};

typedef bool (*mbim_vendor_enqueue_fn)(void *user, const uint8_t *data, uint32_t len);

void mbim_vendor_qmux_reset(struct mbim_vendor_qmux_state *st);

bool mbim_vendor_qmux_handle_ctl_sync(struct mbim_vendor_qmux_state *st,
                                      uint32_t mbim_tid,
                                      uint32_t cid,
                                      const uint8_t *service_id,
                                      const uint8_t *q,
                                      uint32_t q_len,
                                      mbim_vendor_enqueue_fn enqueue,
                                      void *user);

bool mbim_vendor_qmux_has_pending_indication(const struct mbim_vendor_qmux_state *st);
uint32_t mbim_vendor_qmux_take_pending_indication(struct mbim_vendor_qmux_state *st,
                                                  uint8_t *out,
                                                  uint32_t out_size);
void mbim_vendor_qmux_mark_indication_sent(struct mbim_vendor_qmux_state *st);

#endif
