#include "ep0_request.h"

#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

#include "../common/log.h"
#include "../mbim_frontend/usb_transport.h"

#define USB_CDC_SEND_ENCAPSULATED_COMMAND 0x00
#define USB_CDC_GET_ENCAPSULATED_RESPONSE 0x01
#define USB_CDC_SET_LINE_CODING 0x20
#define USB_CDC_GET_LINE_CODING 0x21
#define USB_CDC_SET_CONTROL_LINE_STATE 0x22
#define USB_CDC_GET_NTB_PARAMETERS 0x80

static const char *usb_std_req_name(uint8_t req)
{
    switch (req) {
    case USB_REQ_GET_DESCRIPTOR: return "GET_DESCRIPTOR";
    case USB_REQ_SET_CONFIGURATION: return "SET_CONFIGURATION";
    case USB_REQ_GET_CONFIGURATION: return "GET_CONFIGURATION";
    case USB_REQ_SET_INTERFACE: return "SET_INTERFACE";
    case USB_REQ_GET_INTERFACE: return "GET_INTERFACE";
    case USB_REQ_GET_STATUS: return "GET_STATUS";
    default: return "STD_OTHER";
    }
}

static const char *usb_cdc_req_name(uint8_t req)
{
    switch (req) {
    case USB_CDC_SEND_ENCAPSULATED_COMMAND: return "SEND_ENCAPSULATED_COMMAND";
    case USB_CDC_GET_ENCAPSULATED_RESPONSE: return "GET_ENCAPSULATED_RESPONSE";
    case USB_CDC_SET_LINE_CODING: return "SET_LINE_CODING";
    case USB_CDC_GET_LINE_CODING: return "GET_LINE_CODING";
    case USB_CDC_SET_CONTROL_LINE_STATE: return "SET_CONTROL_LINE_STATE";
    case USB_CDC_GET_NTB_PARAMETERS: return "GET_NTB_PARAMETERS";
    default: return "CDC_OTHER";
    }
}

enum ep0_result ep0_handle_request(int fd,
                                   struct usb_raw_control_event *event,
                                   struct usb_raw_control_io *io,
                                   void *user)
{
    struct ep0_request_context *ctx = user;
    struct usb_ctrlrequest *ctrl = &event->ctrl;

    if (ctrl->bRequestType == 0x21 &&
        ctrl->bRequest == USB_CDC_SEND_ENCAPSULATED_COMMAND) {
        LOG_DBG(EP0, "USB EP0 DISPATCH class req=%s iface=%u wLength=%u",
                usb_cdc_req_name(ctrl->bRequest), ctrl->wIndex, ctrl->wLength);
        return ctx->on_send_encapsulated_command(fd, io, ctrl->wLength, ctx->user);
    }

    if (ctrl->bRequestType == 0xa1 &&
        ctrl->bRequest == USB_CDC_GET_ENCAPSULATED_RESPONSE) {
        LOG_DBG(EP0, "USB EP0 DISPATCH class req=%s iface=%u wLength=%u",
                usb_cdc_req_name(ctrl->bRequest), ctrl->wIndex, ctrl->wLength);
        return ctx->on_get_encapsulated_response(fd, io, ctrl->wLength, ctx->user);
    }

    if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS &&
        ctrl->bRequest == USB_CDC_GET_NTB_PARAMETERS)
    {
        size_t ntb_len = 0;
        const uint8_t *ntb = usb_transport_ntb_params(&ntb_len);
        LOG_DBG(EP0, "GET_NTB_PARAMETERS");
        memcpy(io->data, ntb, ntb_len);
        io->inner.length = ntb_len;
        return EP0_REPLY_REQ;
    }

    if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS &&
        ctrl->bRequest == USB_CDC_SET_LINE_CODING)
    {
        LOG_DBG(EP0, "SET_LINE_CODING iface=%u len=%u", ctrl->wIndex, ctrl->wLength);
        io->inner.length = ctrl->wLength;
        return EP0_REPLY_REQ;
    }

    if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS &&
        ctrl->bRequest == USB_CDC_GET_LINE_CODING)
    {
        size_t lc_len = 0;
        const uint8_t *lc = usb_transport_line_coding(&lc_len);
        LOG_DBG(EP0, "GET_LINE_CODING iface=%u", ctrl->wIndex);
        memcpy(io->data, lc, lc_len);
        io->inner.length = lc_len;
        return EP0_REPLY_REQ;
    }

    if ((ctrl->bRequestType & USB_TYPE_MASK) == USB_TYPE_CLASS &&
        ctrl->bRequest == USB_CDC_SET_CONTROL_LINE_STATE)
    {
        LOG_DBG(EP0, "SET_CONTROL_LINE_STATE iface=%u value=%04x", ctrl->wIndex, ctrl->wValue);
        io->inner.length = 0;
        return EP0_REPLY_REQ;
    }

    switch (ctrl->bRequestType & USB_TYPE_MASK)
    {
    case USB_TYPE_STANDARD:
        switch (ctrl->bRequest)
        {
        case USB_REQ_GET_DESCRIPTOR:
            switch (ctrl->wValue >> 8)
            {
            case USB_DT_DEVICE:
                memcpy(io->data,
                       usb_transport_device_descriptor(),
                       usb_transport_device_descriptor_size());
                io->inner.length = usb_transport_device_descriptor_size();
                return EP0_REPLY_REQ;

            case USB_DT_DEVICE_QUALIFIER:
                memcpy(io->data,
                       usb_transport_qualifier_descriptor(),
                       usb_transport_qualifier_descriptor_size());
                io->inner.length = usb_transport_qualifier_descriptor_size();
                return EP0_REPLY_REQ;

            case USB_DT_CONFIG:
                io->inner.length = usb_transport_build_config(io->data, sizeof(io->data));
                return EP0_REPLY_REQ;

            case USB_DT_STRING:
                io->inner.length = usb_transport_make_string(io->data, sizeof(io->data),
                                                             ctrl->wValue & 0xff);
                return EP0_REPLY_REQ;

            default:
                return EP0_STALL_REQ;
            }

        case USB_REQ_SET_CONFIGURATION:
            LOG_DBG(EP0, "USB STD %s value=%u index=%u eps_enabled=%s",
                    usb_std_req_name(ctrl->bRequest),
                    ctrl->wValue, ctrl->wIndex,
                    *ctx->eps_enabled ? "yes" : "no");
            if (!*ctx->eps_enabled)
            {
                usb_transport_enable_endpoints(fd,
                                               ctx->mbim_ep_int,
                                               ctx->mbim_ep_out,
                                               ctx->mbim_ep_in,
                                               ctx->acm_ep_int,
                                               ctx->acm_ep_out,
                                               ctx->acm_ep_in);

                *ctx->eps_enabled = true;
            }

            ioctl(fd, USB_RAW_IOCTL_VBUS_DRAW, 0x32);
            ioctl(fd, USB_RAW_IOCTL_CONFIGURE, 0);

            io->inner.length = 0;
            return EP0_REPLY_REQ;

        case USB_REQ_GET_CONFIGURATION:
            io->data[0] = 1;
            io->inner.length = 1;
            return EP0_REPLY_REQ;

        case USB_REQ_SET_INTERFACE:
            LOG_INF(EP0, "USB STD SET_INTERFACE if=%u alt=%u",
                    ctrl->wIndex, ctrl->wValue);
            io->inner.length = 0;
            return EP0_REPLY_REQ;

        case USB_REQ_GET_INTERFACE:
            LOG_DBG(EP0, "USB STD GET_INTERFACE if=%u -> alt=0", ctrl->wIndex);
            io->data[0] = 0;
            io->inner.length = 1;
            return EP0_REPLY_REQ;

        case USB_REQ_GET_STATUS:
            io->data[0] = 0;
            io->data[1] = 0;
            io->inner.length = 2;
            return EP0_REPLY_REQ;

        default:
            LOG_WRN(EP0, "USB EP0 unhandled STD req=0x%02x(%s) bmRequestType=0x%02x",
                    ctrl->bRequest, usb_std_req_name(ctrl->bRequest), ctrl->bRequestType);
            return EP0_STALL_REQ;
        }

    default:
        LOG_WRN(EP0, "USB EP0 unhandled req type bmRequestType=0x%02x req=0x%02x(%s)",
                ctrl->bRequestType, ctrl->bRequest, usb_cdc_req_name(ctrl->bRequest));
        return EP0_STALL_REQ;
    }
}
