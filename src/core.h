#ifndef CORE_H
#define CORE_H

#include <stdbool.h>
#include <stdint.h>

#include "modem_state/modem_state.h"

extern int acm_ep_out;
extern int acm_ep_in;
extern struct modem_state g_modem_state;

int usb_raw_open_dev(void);
void usb_raw_init_dev(int fd, const char *driver, const char *device);
void ep0_loop(int fd);
uint32_t core_debug_last_ep0_get_id(void);
bool core_debug_last_ep0_get_is_ps_attached(void);
uint32_t core_debug_last_ep0_get_len(void);
bool core_debug_use_static_ep0_in_buf(void);

#endif
