#ifndef EP0_DISPATCH_H
#define EP0_DISPATCH_H

#include "../mbim_frontend/usb_transport.h"

enum ep0_result
{
    EP0_STALL_REQ = 0,
    EP0_REPLY_REQ = 1,
    EP0_CONSUMED_REQ = 2,
};

typedef enum ep0_result (*ep0_request_handler_fn)(int fd,
                                                   struct usb_raw_control_event *event,
                                                   struct usb_raw_control_io *io,
                                                   void *user);

typedef void (*ep0_tick_fn)(void *user);

void ep0_dispatch_loop(int fd,
                       ep0_request_handler_fn handler,
                       ep0_tick_fn tick,
                       void *user);

#endif
