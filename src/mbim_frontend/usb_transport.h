#ifndef USB_TRANSPORT_H
#define USB_TRANSPORT_H

#include <linux/usb/ch9.h>
#include <linux/usb/raw_gadget.h>
#include <stddef.h>
#include <stdint.h>

struct usb_raw_control_event
{
    struct usb_raw_event inner;
    struct usb_ctrlrequest ctrl;
};

struct usb_raw_control_io
{
    struct usb_raw_ep_io inner;
    char data[4096];
};

int usb_raw_open_dev(void);
void usb_raw_init_dev(int fd, const char *driver, const char *device);

int usb_transport_ep0_write(int fd, struct usb_raw_control_io *io);
int usb_transport_ep0_read(int fd, struct usb_raw_control_io *io);
void usb_transport_ep0_stall(int fd);

const uint8_t *usb_transport_ntb_params(size_t *len);
const uint8_t *usb_transport_line_coding(size_t *len);

int usb_transport_build_config(char *data, int length);
int usb_transport_make_string(char *data, int length, int idx);
size_t usb_transport_device_descriptor_size(void);
const void *usb_transport_device_descriptor(void);
size_t usb_transport_qualifier_descriptor_size(void);
const void *usb_transport_qualifier_descriptor(void);

void usb_transport_enable_endpoints(int fd,
                                    int *mbim_ep_int,
                                    int *mbim_ep_out,
                                    int *mbim_ep_in,
                                    int *acm_ep_int,
                                    int *acm_ep_out,
                                    int *acm_ep_in);

#endif
