#include "ims_ip.h"

#include <errno.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static uint32_t checksum_add(uint32_t sum, const uint8_t *data, size_t len)
{
    size_t i;

    for (i = 0; i + 1 < len; i += 2)
        sum += rd16(data + i);
    if (i < len)
        sum += (uint16_t)data[i] << 8;
    return sum;
}

static uint16_t checksum_finish(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t ipv4_header_checksum(const uint8_t *hdr, size_t hdr_len)
{
    return checksum_finish(checksum_add(0, hdr, hdr_len));
}

static uint16_t udp_checksum_ipv4(const uint8_t src_ip[4],
                                  const uint8_t dst_ip[4],
                                  const uint8_t *udp,
                                  size_t udp_len)
{
    uint8_t pseudo[12];
    uint32_t sum = 0;

    memcpy(pseudo, src_ip, 4);
    memcpy(pseudo + 4, dst_ip, 4);
    pseudo[8] = 0;
    pseudo[9] = 17;
    wr16(pseudo + 10, (uint16_t)udp_len);

    sum = checksum_add(sum, pseudo, sizeof(pseudo));
    sum = checksum_add(sum, udp, udp_len);
    return checksum_finish(sum);
}

int ims_ip_parse_udp_ipv4(const uint8_t *packet,
                          size_t packet_len,
                          struct ims_udp_packet *out)
{
    size_t ihl;
    size_t total_len;
    size_t udp_len;
    const uint8_t *udp;

    if (!packet || !out || packet_len < 28)
        return -EINVAL;
    if ((packet[0] >> 4) != 4)
        return -EPROTONOSUPPORT;
    ihl = (size_t)(packet[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > packet_len)
        return -EINVAL;
    if (packet[9] != 17)
        return -EPROTONOSUPPORT;

    total_len = rd16(packet + 2);
    if (total_len < ihl + 8 || total_len > packet_len)
        return -EINVAL;

    udp = packet + ihl;
    udp_len = rd16(udp + 4);
    if (udp_len < 8 || ihl + udp_len > total_len)
        return -EINVAL;

    memset(out, 0, sizeof(*out));
    memcpy(out->src_ip, packet + 12, 4);
    memcpy(out->dst_ip, packet + 16, 4);
    out->src_port = rd16(udp);
    out->dst_port = rd16(udp + 2);
    out->payload = udp + 8;
    out->payload_len = udp_len - 8;
    return 0;
}

int ims_ip_build_udp_ipv4(uint8_t *out,
                          size_t out_len,
                          const uint8_t src_ip[4],
                          const uint8_t dst_ip[4],
                          uint16_t src_port,
                          uint16_t dst_port,
                          const uint8_t *payload,
                          size_t payload_len)
{
    size_t udp_len = 8 + payload_len;
    size_t total_len = 20 + udp_len;
    uint8_t *udp;
    uint16_t csum;

    if (!out || !src_ip || !dst_ip || (!payload && payload_len > 0))
        return -EINVAL;
    if (payload_len > 0xffffu - 28 || out_len < total_len)
        return -EMSGSIZE;

    memset(out, 0, total_len);
    out[0] = 0x45;
    out[1] = 0;
    wr16(out + 2, (uint16_t)total_len);
    wr16(out + 4, 0);
    wr16(out + 6, 0x4000);
    out[8] = 64;
    out[9] = 17;
    memcpy(out + 12, src_ip, 4);
    memcpy(out + 16, dst_ip, 4);
    wr16(out + 10, ipv4_header_checksum(out, 20));

    udp = out + 20;
    wr16(udp, src_port);
    wr16(udp + 2, dst_port);
    wr16(udp + 4, (uint16_t)udp_len);
    if (payload_len > 0)
        memcpy(udp + 8, payload, payload_len);
    csum = udp_checksum_ipv4(src_ip, dst_ip, udp, udp_len);
    wr16(udp + 6, csum ? csum : 0xffffu);

    return (int)total_len;
}
