#ifndef MBIM_INDICATIONS_H
#define MBIM_INDICATIONS_H

#include <stdbool.h>
#include <stdint.h>

struct modem_state;

struct mbim_indications_state {
    bool sms_cfg_sent;
    bool packet_service_sent;
    bool register_state_sent;
    bool radio_state_sent;
};

typedef bool (*mbim_indications_enqueue_fn)(void *user,
                                            const uint8_t *data,
                                            uint32_t len);

void mbim_indications_reset(struct mbim_indications_state *st);

bool mbim_indications_emit_sms_configuration(
    struct mbim_indications_state *st,
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_sms_message_store_status(
    mbim_indications_enqueue_fn enqueue,
    void *user,
    uint32_t message_index);

bool mbim_indications_emit_sms_read(mbim_indications_enqueue_fn enqueue,
                                    void *user,
                                    const uint8_t *info, uint32_t info_len);

bool mbim_indications_emit_packet_service(
    struct mbim_indications_state *st,
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_packet_service_attaching(
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_packet_service_attached(
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_packet_service_detached(
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_register_state_searching(
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_register_state_deregistered(
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_register_state_home(
    mbim_indications_enqueue_fn enqueue,
    void *user,
    const struct modem_state *state);

bool mbim_indications_emit_register_state(
    struct mbim_indications_state *st,
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_radio_state(
    struct mbim_indications_state *st,
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_connect(
    mbim_indications_enqueue_fn enqueue,
    void *user);

bool mbim_indications_emit_lte_attach_status(
    mbim_indications_enqueue_fn enqueue,
    void *user,
    const struct modem_state *state);

#endif
