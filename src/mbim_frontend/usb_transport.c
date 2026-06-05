#define _GNU_SOURCE

#include "usb_transport.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "../common/log.h"
#include "../common/utils.h"
#include "../core.h"

static bool usb_buf_is_ps_attached(const uint8_t *d, uint32_t len)
{
    if (!d || len < 72)
        return false;
    if (get_le32(&d[0]) != 0x00000007)
        return false;
    if (get_le32(&d[36]) != 10)
        return false;
    return get_le32(&d[48]) == 2;
}

static void usb_log_hex(const char *tag, const uint8_t *buf, uint32_t len)
{
    uint32_t i;
    char line[3 * 16 + 1];

    for (i = 0; i < len; i += 16) {
        uint32_t j;
        uint32_t chunk = (len - i > 16) ? 16 : (len - i);
        for (j = 0; j < chunk; j++)
            snprintf(&line[j * 3], sizeof(line) - (j * 3), "%02x ", buf[i + j]);
        line[chunk * 3] = '\0';
        LOG_TRC(EP0, "%s off=%u %s", tag, i, line);
    }
}

#define BCD_USB 0x0200
#define USB_VENDOR 0x2c7c
#define USB_PRODUCT 0x0800

#define EP_MAX_PACKET_CONTROL 64
#define EP_MAX_PACKET_BULK 512
#define EP_MAX_PACKET_INT 16

#define ENABLE_EP(var, desc)                                              \
    do                                                                    \
    {                                                                     \
        errno = 0;                                                        \
        var = ioctl(fd, USB_RAW_IOCTL_EP_ENABLE, desc);                   \
        LOG_DBG(CORE, #var "=%d errno=%d (%s)", var, errno, strerror(errno)); \
    } while (0)

static struct usb_device_descriptor usb_device = {
    .bLength = USB_DT_DEVICE_SIZE,
    .bDescriptorType = USB_DT_DEVICE,
    .bcdUSB = __constant_cpu_to_le16(BCD_USB),
    .bDeviceClass = 0xef,
    .bDeviceSubClass = 0x02,
    .bDeviceProtocol = 0x01,
    .bMaxPacketSize0 = EP_MAX_PACKET_CONTROL,
    .idVendor = __constant_cpu_to_le16(USB_VENDOR),
    .idProduct = __constant_cpu_to_le16(USB_PRODUCT),
    .bcdDevice = __constant_cpu_to_le16(0x0100),
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

static struct usb_qualifier_descriptor usb_qualifier = {
    .bLength = sizeof(struct usb_qualifier_descriptor),
    .bDescriptorType = USB_DT_DEVICE_QUALIFIER,
    .bcdUSB = __constant_cpu_to_le16(BCD_USB),
    .bDeviceClass = 0xef,
    .bDeviceSubClass = 0x02,
    .bDeviceProtocol = 0x01,
    .bMaxPacketSize0 = EP_MAX_PACKET_CONTROL,
    .bNumConfigurations = 1,
};

static const uint8_t ntb_params[28] = {
    0x1c, 0x00,
    0x01, 0x00,
    0x00, 0x10, 0x00, 0x00,
    0x04, 0x00,
    0x00, 0x00,
    0x04, 0x00,
    0x00, 0x00,
    0x00, 0x10, 0x00, 0x00,
    0x04, 0x00,
    0x00, 0x00,
    0x04, 0x00,
    0x00, 0x00,
};

static const uint8_t line_coding[7] = {
    0x00, 0xc2, 0x01, 0x00,
    0x00,
    0x00,
    0x08,
};

static struct usb_endpoint_descriptor ep_int_in = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = USB_DIR_IN | 1,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = __constant_cpu_to_le16(EP_MAX_PACKET_INT),
    .bInterval = 9,
};

static struct usb_endpoint_descriptor ep_bulk_out = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = USB_DIR_OUT | 2,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = __constant_cpu_to_le16(EP_MAX_PACKET_BULK),
};

static struct usb_endpoint_descriptor ep_bulk_in = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = USB_DIR_IN | 3,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = __constant_cpu_to_le16(EP_MAX_PACKET_BULK),
};

static struct usb_endpoint_descriptor ep_acm_int_in = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = USB_DIR_IN | 4,
    .bmAttributes = USB_ENDPOINT_XFER_INT,
    .wMaxPacketSize = __constant_cpu_to_le16(16),
    .bInterval = 9,
};

static struct usb_endpoint_descriptor ep_acm_bulk_out = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = USB_DIR_OUT | 5,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = __constant_cpu_to_le16(512),
};

static struct usb_endpoint_descriptor ep_acm_bulk_in = {
    .bLength = USB_DT_ENDPOINT_SIZE,
    .bDescriptorType = USB_DT_ENDPOINT,
    .bEndpointAddress = USB_DIR_IN | 6,
    .bmAttributes = USB_ENDPOINT_XFER_BULK,
    .wMaxPacketSize = __constant_cpu_to_le16(512),
};

int usb_raw_open_dev(void)
{
    int fd = open("/dev/raw-gadget", O_RDWR);
    if (fd < 0) {
        perror("open /dev/raw-gadget");
        exit(EXIT_FAILURE);
    }
    return fd;
}

void usb_raw_init_dev(int fd, const char *driver, const char *device)
{
    struct usb_raw_init arg;
    memset(&arg, 0, sizeof(arg));

    strcpy((char *)&arg.driver_name[0], driver);
    strcpy((char *)&arg.device_name[0], device);
    arg.speed = USB_SPEED_HIGH;

    if (ioctl(fd, USB_RAW_IOCTL_INIT, &arg) < 0) {
        perror("USB_RAW_IOCTL_INIT");
        exit(EXIT_FAILURE);
    }

    if (ioctl(fd, USB_RAW_IOCTL_RUN, 0) < 0) {
        perror("USB_RAW_IOCTL_RUN");
        exit(EXIT_FAILURE);
    }
}

int usb_transport_ep0_write(int fd, struct usb_raw_control_io *io)
{
    uint32_t crit_id = core_debug_last_ep0_get_id();
    bool crit_ctx = core_debug_last_ep0_get_is_ps_attached();
    LOG_DBG(EP0, "USB EP0_WRITE submit ep=%u len=%u data_ptr=%p",
            io->inner.ep, io->inner.length, (void *)io->data);
    if (crit_ctx || usb_buf_is_ps_attached((const uint8_t *)io->data, io->inner.length)) {
        LOG_DBG(EP0,
                "critical_ep0_write_submit req=GET_ENCAPS id=%u len=%u buf_ptr=%p",
                crit_id, io->inner.length, (void *)io->data);
        usb_log_hex("critical_ep0_write_payload", (const uint8_t *)io->data, io->inner.length);
    }
    int rv = ioctl(fd, USB_RAW_IOCTL_EP0_WRITE, (struct usb_raw_ep_io *)io);
    if (rv < 0) {
        LOG_ERR(EP0, "USB EP0_WRITE error rv=%d errno=%d", rv, errno);
        perror("USB_RAW_IOCTL_EP0_WRITE");
        exit(EXIT_FAILURE);
    }
    LOG_DBG(EP0, "USB EP0_WRITE done rv=%d requested=%u", rv, io->inner.length);
    if (crit_ctx || usb_buf_is_ps_attached((const uint8_t *)io->data, io->inner.length)) {
        LOG_DBG(EP0,
                "critical_ep0_write_done req=GET_ENCAPS id=%u rv=%d requested=%u",
                crit_id, rv, io->inner.length);
        LOG_DBG(EP0, "CRITICAL ATTACHED EP0_WRITE_DONE id=%u rv=%d", crit_id, rv);
    }
    return rv;
}

int usb_transport_ep0_read(int fd, struct usb_raw_control_io *io)
{
    LOG_DBG(EP0, "USB EP0_READ submit ep=%u len=%u data_ptr=%p",
            io->inner.ep, io->inner.length, (void *)io->data);
    int rv = ioctl(fd, USB_RAW_IOCTL_EP0_READ, (struct usb_raw_ep_io *)io);
    if (rv < 0) {
        LOG_ERR(EP0, "USB EP0_READ error rv=%d errno=%d", rv, errno);
        perror("USB_RAW_IOCTL_EP0_READ");
        exit(EXIT_FAILURE);
    }
    LOG_DBG(EP0, "USB EP0_READ done rv=%d requested=%u", rv, io->inner.length);
    return rv;
}

void usb_transport_ep0_stall(int fd)
{
    LOG_WRN(EP0, "USB EP0_STALL submit");
    int rv = ioctl(fd, USB_RAW_IOCTL_EP0_STALL, 0);
    if (rv < 0) {
        perror("USB_RAW_IOCTL_EP0_STALL");
        exit(EXIT_FAILURE);
    }
}

const uint8_t *usb_transport_ntb_params(size_t *len)
{
    *len = sizeof(ntb_params);
    LOG_TRC(CORE, "NTB params len=%zu", *len);
    return ntb_params;
}

const uint8_t *usb_transport_line_coding(size_t *len)
{
    *len = sizeof(line_coding);
    return line_coding;
}

int usb_transport_build_config(char *data, int length)
{
    LOG_DBG(CORE,
            "USB CFG static eps: mbim_int=0x%02x mbim_out=0x%02x mbim_in=0x%02x acm_int=0x%02x acm_out=0x%02x acm_in=0x%02x",
            ep_int_in.bEndpointAddress,
            ep_bulk_out.bEndpointAddress,
            ep_bulk_in.bEndpointAddress,
            ep_acm_int_in.bEndpointAddress,
            ep_acm_bulk_out.bEndpointAddress,
            ep_acm_bulk_in.bEndpointAddress);

    uint8_t desc[] = {
        0x09, USB_DT_CONFIG, 0x00, 0x00, 0x04, 0x01, 0x00,
        USB_CONFIG_ATT_ONE | USB_CONFIG_ATT_SELFPOWER, 0x32,
        0x08, USB_DT_INTERFACE_ASSOCIATION, 0x00, 0x02, 0x02, 0x0e, 0x00, 0x00,
        0x09, USB_DT_INTERFACE, 0x00, 0x00, 0x01, 0x02, 0x0e, 0x00, 0x00,
        0x05, 0x24, 0x00, 0x10, 0x01,
        0x05, 0x24, 0x06, 0x00, 0x01,
        0x0c, 0x24, 0x1b, 0x00, 0x01, 0x00, 0x10, 0x08, 0x80, 0x05, 0x00, 0x06,
        0x08, 0x24, 0x1c, 0x00, 0x01, 0x20, 0x00, 0x00,
        0x07, USB_DT_ENDPOINT, 0x81, USB_ENDPOINT_XFER_INT, 0x10, 0x00, 0x09,
        0x09, USB_DT_INTERFACE, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x00,
        0x09, USB_DT_INTERFACE, 0x01, 0x01, 0x02, 0x0a, 0x00, 0x02, 0x00,
        0x07, USB_DT_ENDPOINT, 0x02, USB_ENDPOINT_XFER_BULK, 0x00, 0x02, 0x00,
        0x07, USB_DT_ENDPOINT, 0x83, USB_ENDPOINT_XFER_BULK, 0x00, 0x02, 0x00,
        0x08, USB_DT_INTERFACE_ASSOCIATION, 0x02, 0x02, 0x02, 0x02, 0x01, 0x00,
        0x09, USB_DT_INTERFACE, 0x02, 0x00, 0x01, 0x02, 0x02, 0x01, 0x00,
        0x05, 0x24, 0x00, 0x10, 0x01,
        0x04, 0x24, 0x02, 0x02,
        0x05, 0x24, 0x06, 0x02, 0x03,
        0x05, 0x24, 0x01, 0x00, 0x03,
        0x07, USB_DT_ENDPOINT, 0x84, USB_ENDPOINT_XFER_INT, 0x10, 0x00, 0x09,
        0x09, USB_DT_INTERFACE, 0x03, 0x00, 0x02, 0x0a, 0x00, 0x00, 0x00,
        0x07, USB_DT_ENDPOINT, 0x05, USB_ENDPOINT_XFER_BULK, 0x00, 0x02, 0x00,
        0x07, USB_DT_ENDPOINT, 0x86, USB_ENDPOINT_XFER_BULK, 0x00, 0x02, 0x00,
    };

    uint16_t total = sizeof(desc);
    desc[2] = total & 0xff;
    desc[3] = total >> 8;

    assert(length >= total);
    memcpy(data, desc, total);
    return total;
}

int usb_transport_make_string(char *data, int length, int idx)
{
    const char *s = "";

    if (idx == 0) {
        data[0] = 4;
        data[1] = USB_DT_STRING;
        data[2] = 0x09;
        data[3] = 0x04;
        return 4;
    }

    if (idx == 1)
        s = "Quectel";
    else if (idx == 2)
        s = "Virtual MBIM Modem";
    else if (idx == 3)
        s = "deadbeef0001";
    else
        s = "x";

    int slen = strlen(s);
    int out = 2 + slen * 2;
    if (out > length)
        out = length;

    data[0] = out;
    data[1] = USB_DT_STRING;

    for (int i = 0; i < slen && 2 + i * 2 + 1 < length; i++) {
        data[2 + i * 2] = s[i];
        data[3 + i * 2] = 0x00;
    }

    return out;
}

size_t usb_transport_device_descriptor_size(void)
{
    return sizeof(usb_device);
}

const void *usb_transport_device_descriptor(void)
{
    return &usb_device;
}

size_t usb_transport_qualifier_descriptor_size(void)
{
    return sizeof(usb_qualifier);
}

const void *usb_transport_qualifier_descriptor(void)
{
    return &usb_qualifier;
}

void usb_transport_enable_endpoints(int fd,
                                    int *mbim_ep_int,
                                    int *mbim_ep_out,
                                    int *mbim_ep_in,
                                    int *acm_ep_int,
                                    int *acm_ep_out,
                                    int *acm_ep_in)
{
    LOG_DBG(CORE,
            "USB CFG enable begin desc_addrs mbim_int=0x%02x mbim_out=0x%02x mbim_in=0x%02x acm_int=0x%02x acm_out=0x%02x acm_in=0x%02x",
            ep_int_in.bEndpointAddress,
            ep_bulk_out.bEndpointAddress,
            ep_bulk_in.bEndpointAddress,
            ep_acm_int_in.bEndpointAddress,
            ep_acm_bulk_out.bEndpointAddress,
            ep_acm_bulk_in.bEndpointAddress);

    ENABLE_EP(*mbim_ep_int, &ep_int_in);
    ENABLE_EP(*mbim_ep_out, &ep_bulk_out);
    ENABLE_EP(*mbim_ep_in, &ep_bulk_in);

    ENABLE_EP(*acm_ep_int, &ep_acm_int_in);
    ENABLE_EP(*acm_ep_out, &ep_acm_bulk_out);
    ENABLE_EP(*acm_ep_in, &ep_acm_bulk_in);

    LOG_INF(CORE, "EP enabled: mbim int=%d out=%d in=%d | acm int=%d out=%d in=%d",
           *mbim_ep_int, *mbim_ep_out, *mbim_ep_in,
           *acm_ep_int, *acm_ep_out, *acm_ep_in);
    LOG_DBG(CORE, "USB CFG runtime epnums mbim_notify=%d mbim_data_out=%d mbim_data_in=%d acm_notify=%d acm_out=%d acm_in=%d",
            *mbim_ep_int, *mbim_ep_out, *mbim_ep_in,
            *acm_ep_int, *acm_ep_out, *acm_ep_in);
    LOG_DBG(CORE, "endpoint enabled ep_int=%d ep_out=%d ep_in=%d",
            *mbim_ep_int, *mbim_ep_out, *mbim_ep_in);
}
