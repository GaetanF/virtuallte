#include "ep0_dispatch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "../common/log.h"
#include "../core.h"
#include "../mbim_frontend/usb_transport.h"

/* raw-gadget flag asking the UDC to terminate an IN transfer with a ZLP when
 * the data length is an exact multiple of the endpoint's max packet size.
 * Guarded in case the kernel uapi header predates it. */
#ifndef USB_RAW_IO_FLAGS_ZERO
#define USB_RAW_IO_FLAGS_ZERO 0x0001
#endif

static const char *usb_dir_name(uint8_t bm_request_type)
{
    return (bm_request_type & USB_DIR_IN) ? "in" : "out";
}

static const char *usb_type_name(uint8_t bm_request_type)
{
    switch (bm_request_type & USB_TYPE_MASK) {
    case USB_TYPE_STANDARD: return "standard";
    case USB_TYPE_CLASS: return "class";
    case USB_TYPE_VENDOR: return "vendor";
    default: return "reserved";
    }
}

static const char *usb_recip_name(uint8_t bm_request_type)
{
    switch (bm_request_type & USB_RECIP_MASK) {
    case USB_RECIP_DEVICE: return "device";
    case USB_RECIP_INTERFACE: return "interface";
    case USB_RECIP_ENDPOINT: return "endpoint";
    case USB_RECIP_OTHER: return "other";
    default: return "unknown";
    }
}

static const char *usb_req_name(uint8_t req)
{
    switch (req) {
    case 0x00: return "SEND_ENCAPSULATED_COMMAND";
    case 0x01: return "GET_ENCAPSULATED_RESPONSE";
    case 0x20: return "SET_LINE_CODING";
    case 0x21: return "GET_LINE_CODING";
    case 0x22: return "SET_CONTROL_LINE_STATE";
    case 0x80: return "GET_NTB_PARAMETERS";
    default: return "OTHER";
    }
}

void ep0_dispatch_loop(int fd,
                       ep0_request_handler_fn handler,
                       ep0_tick_fn tick,
                       void *user)
{
    static struct usb_raw_control_io g_static_in_io;
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    while (true)
    {
        struct usb_raw_control_event event;
        struct usb_raw_control_io io;
        enum ep0_result result;

        if (tick)
            tick(user);

        memset(&event, 0, sizeof(event));
        event.inner.length = sizeof(event.ctrl);

        if (ioctl(fd, USB_RAW_IOCTL_EVENT_FETCH, (struct usb_raw_event *)&event) < 0) {
            if (errno == EAGAIN || errno == EINTR) {
                usleep(1000);
                continue;
            }
            perror("USB_RAW_IOCTL_EVENT_FETCH");
            exit(EXIT_FAILURE);
        }

        if (event.inner.type == USB_RAW_EVENT_CONNECT)
        {
            LOG_INF(EP0, "EVENT CONNECT");
            continue;
        }

        if (event.inner.type == USB_RAW_EVENT_RESET)
        {
            LOG_INF(EP0, "EVENT RESET");
            continue;
        }

        if (event.inner.type == USB_RAW_EVENT_DISCONNECT)
        {
            LOG_INF(EP0, "EVENT DISCONNECT");
            continue;
        }

        if (event.inner.type != USB_RAW_EVENT_CONTROL)
        {
            LOG_DBG(EP0, "EVENT type=%u len=%u", event.inner.type, event.inner.length);
            continue;
        }

        memset(&io, 0, sizeof(io));
        io.inner.ep = 0;
        io.inner.flags = 0;
        io.inner.length = 0;

        LOG_DBG(EP0,
                "USB EP0 SETUP dir=%s type=%s recip=%s req=0x%02x(%s) wValue=0x%04x wIndex=%u wLength=%u",
                usb_dir_name(event.ctrl.bRequestType),
                usb_type_name(event.ctrl.bRequestType),
                usb_recip_name(event.ctrl.bRequestType),
                event.ctrl.bRequest,
                usb_req_name(event.ctrl.bRequest),
                event.ctrl.wValue,
                event.ctrl.wIndex,
                event.ctrl.wLength);

        result = handler(fd, &event, &io, user);

        LOG_DBG(EP0, "USB EP0 HANDLER result=%d req=0x%02x io_len=%u",
                result, event.ctrl.bRequest, io.inner.length);

        if (result == EP0_CONSUMED_REQ) {
            LOG_DBG(EP0, "USB EP0 CONSUMED req=0x%02x(%s)",
                    event.ctrl.bRequest, usb_req_name(event.ctrl.bRequest));
            continue;
        }

        if (result == EP0_STALL_REQ)
        {
            LOG_WRN(EP0,
                    "USB EP0 STALL req=0x%02x(%s) bmRequestType=0x%02x wValue=0x%04x wIndex=%u wLength=%u",
                    event.ctrl.bRequest,
                    usb_req_name(event.ctrl.bRequest),
                    event.ctrl.bRequestType,
                    event.ctrl.wValue,
                    event.ctrl.wIndex,
                    event.ctrl.wLength);
            usb_transport_ep0_stall(fd);
            continue;
        }

        if (event.ctrl.wLength < io.inner.length)
            io.inner.length = event.ctrl.wLength;

        /*
         * Control-IN data stage: when we return fewer bytes than the host
         * asked for (wLength) and the length is an exact multiple of the EP0
         * max packet size, USB requires a terminating zero-length packet so
         * the host knows the data is complete. Ask the UDC to append it via
         * req->zero. Without this, e.g. a 256-byte MBIM response to a
         * wLength=4096 GET_ENCAPSULATED_RESPONSE never completes on the host
         * (256 = 4*64), it times out and closes the session. Setting the flag
         * is harmless when the length is not a multiple (UDC adds no ZLP).
         */
        if ((event.ctrl.bRequestType & USB_DIR_IN) &&
            io.inner.length > 0 &&
            io.inner.length < event.ctrl.wLength)
            io.inner.flags |= USB_RAW_IO_FLAGS_ZERO;

        struct usb_raw_control_io *active_io = &io;

        LOG_DBG(EP0,
                "USB EP0 XFER_PREP dir=%s req=0x%02x host_wLength=%u io_len=%u data_ptr=%p",
                usb_dir_name(event.ctrl.bRequestType),
                event.ctrl.bRequest,
                event.ctrl.wLength,
                io.inner.length,
                (void *)io.data);

        if ((event.ctrl.bRequestType & USB_DIR_IN) &&
            event.ctrl.bRequest == 0x01 &&
            core_debug_use_static_ep0_in_buf()) {
            memcpy(&g_static_in_io, &io, sizeof(io));
            active_io = &g_static_in_io;
            LOG_TRC(EP0, "USB GET_ENCAPS final_buf source=static ptr=%p len=%u",
                    (void *)g_static_in_io.data, g_static_in_io.inner.length);
        } else if ((event.ctrl.bRequestType & USB_DIR_IN) && event.ctrl.bRequest == 0x01) {
            LOG_TRC(EP0, "USB GET_ENCAPS final_buf source=stack ptr=%p len=%u",
                    (void *)io.data, io.inner.length);
        }

        if (event.ctrl.bRequestType & USB_DIR_IN) {
            usb_transport_ep0_write(fd, active_io);
            LOG_DBG(EP0, "USB EP0 COMPLETE dir=in req=0x%02x sent=%u",
                    event.ctrl.bRequest, active_io->inner.length);
        } else {
            usb_transport_ep0_read(fd, &io);
            LOG_DBG(EP0, "USB EP0 COMPLETE dir=out req=0x%02x recv=%u",
                    event.ctrl.bRequest, io.inner.length);
        }
    }
}
