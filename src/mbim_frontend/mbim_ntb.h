#ifndef MBIM_NTB_H
#define MBIM_NTB_H

/*
 * NCM Transfer Block (NTB16) framing for the MBIM data endpoints.
 *
 * MBIM carries IP datagrams over the bulk data endpoints wrapped in NCM
 * transfer blocks (NTH16 + NDP16), NOT as raw IP. The device advertises NTB16
 * via the NTB parameter structure (usb_transport ntb_params). These helpers
 * deframe host->device NTBs (uplink) and frame device->host NTBs (downlink).
 *
 * Layout:
 *   NTH16 (12B): dwSignature 'NCMH' | wHeaderLength | wSequence |
 *                wBlockLength | wNdpIndex
 *   NDP16  (8B + entries): dwSignature 'IPS<sid>' | wLength | wNextNdpIndex |
 *                {wDatagramIndex, wDatagramLength} ... {0,0}
 */

#include <stdint.h>

#define MBIM_NTH16_SIGNATURE 0x484D434EU  /* 'N''C''M''H' little-endian */
#define MBIM_NDP16_SIGNATURE 0x00535049U  /* 'I''P''S' + session id 0    */
#define MBIM_NDP16_SIG_MASK  0x00FFFFFFU  /* match 'IPS', ignore session  */

/*
 * Deframe a host->device NTB16. Calls cb() for every datagram found.
 * Returns the number of datagrams, or -1 if the block is not a valid NTH16.
 */
int mbim_ntb16_deframe(const uint8_t *ntb, uint32_t len,
                       void (*cb)(void *user, const uint8_t *dg, uint32_t dg_len),
                       void *user);

/*
 * Frame a single IP datagram into a device->host NTB16 at `out` (capacity
 * `cap`). Returns the total NTB length, or 0 on error (bad args / too small).
 */
uint32_t mbim_ntb16_frame_single(uint8_t *out, uint32_t cap,
                                 const uint8_t *ip, uint32_t ip_len,
                                 uint16_t sequence);

#endif
