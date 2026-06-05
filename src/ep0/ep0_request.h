#ifndef EP0_REQUEST_H
#define EP0_REQUEST_H

#include <stdbool.h>
#include <stdint.h>

#include "ep0_dispatch.h"

struct ep0_request_context {
    bool *eps_enabled;
    int *mbim_ep_int;
    int *mbim_ep_out;
    int *mbim_ep_in;
    int *acm_ep_int;
    int *acm_ep_out;
    int *acm_ep_in;

    enum ep0_result (*on_send_encapsulated_command)(int fd,
                                                     struct usb_raw_control_io *io,
                                                     uint16_t w_length,
                                                     void *user);
    enum ep0_result (*on_get_encapsulated_response)(int fd,
                                                     struct usb_raw_control_io *io,
                                                     uint16_t w_length,
                                                     void *user);
    void *user;
};

enum ep0_result ep0_handle_request(int fd,
                                   struct usb_raw_control_event *event,
                                   struct usb_raw_control_io *io,
                                   void *user);

#endif
