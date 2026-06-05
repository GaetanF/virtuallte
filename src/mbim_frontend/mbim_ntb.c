#include "mbim_ntb.h"

#include <string.h>

static inline uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

int mbim_ntb16_deframe(const uint8_t *ntb, uint32_t len,
                       void (*cb)(void *user, const uint8_t *dg, uint32_t dg_len),
                       void *user)
{
    uint32_t block_len;
    uint32_t ndp_index;
    int count = 0;

    if (!ntb || len < 12 || !cb)
        return -1;
    if (rd32(ntb + 0) != MBIM_NTH16_SIGNATURE)
        return -1;

    block_len = rd16(ntb + 8);                 /* wBlockLength */
    if (block_len == 0 || block_len > len)
        block_len = len;                       /* tolerate a short/zero value */
    ndp_index = rd16(ntb + 10);                /* wNdpIndex */

    while (ndp_index != 0 && ndp_index + 8 <= block_len) {
        uint32_t sig = rd32(ntb + ndp_index);
        uint32_t ndp_len = rd16(ntb + ndp_index + 4);
        uint32_t next_ndp = rd16(ntb + ndp_index + 6);
        uint32_t ndp_end = ndp_index + ndp_len;
        uint32_t p;

        if ((sig & MBIM_NDP16_SIG_MASK) != MBIM_NDP16_SIGNATURE)
            break;                             /* not an IPS NDP */
        if (ndp_len < 8 || ndp_end > block_len)
            ndp_end = block_len;

        for (p = ndp_index + 8; p + 4 <= ndp_end; p += 4) {
            uint32_t dg_index = rd16(ntb + p);
            uint32_t dg_len = rd16(ntb + p + 2);

            if (dg_index == 0 && dg_len == 0)
                break;                         /* terminating null entry */
            if (dg_len == 0 || dg_index + dg_len > block_len)
                continue;                      /* skip bogus entry */

            cb(user, ntb + dg_index, dg_len);
            count++;
        }

        /* Require the chain to move strictly forward: this rejects not only a
         * self-loop but any multi-NDP cycle that would otherwise loop forever. */
        if (next_ndp == 0 || next_ndp <= ndp_index)
            break;
        ndp_index = next_ndp;
    }

    return count;
}

uint32_t mbim_ntb16_frame_single(uint8_t *out, uint32_t cap,
                                 const uint8_t *ip, uint32_t ip_len,
                                 uint16_t sequence)
{
    uint32_t dg_off = 12;                       /* datagram right after NTH16 */
    uint32_t ndp_off = (dg_off + ip_len + 3u) & ~3u;  /* NDP 4-byte aligned   */
    uint32_t ndp_len = 16;                      /* 8 hdr + 1 entry + null      */
    uint32_t total = ndp_off + ndp_len;

    if (!out || !ip || ip_len == 0 || total > cap || total > 0xFFFFu)
        return 0;

    memset(out, 0, total);

    /* NTH16 */
    wr32(out + 0, MBIM_NTH16_SIGNATURE);
    wr16(out + 4, 12);                          /* wHeaderLength */
    wr16(out + 6, sequence);                    /* wSequence     */
    wr16(out + 8, (uint16_t)total);             /* wBlockLength  */
    wr16(out + 10, (uint16_t)ndp_off);          /* wNdpIndex     */

    /* datagram */
    memcpy(out + dg_off, ip, ip_len);

    /* NDP16 */
    wr32(out + ndp_off + 0, MBIM_NDP16_SIGNATURE);
    wr16(out + ndp_off + 4, (uint16_t)ndp_len); /* wLength       */
    wr16(out + ndp_off + 6, 0);                 /* wNextNdpIndex */
    wr16(out + ndp_off + 8, (uint16_t)dg_off);  /* wDatagramIndex  */
    wr16(out + ndp_off + 10, (uint16_t)ip_len); /* wDatagramLength */
    wr16(out + ndp_off + 12, 0);                /* null entry index  */
    wr16(out + ndp_off + 14, 0);                /* null entry length */

    return total;
}
