#ifndef IMS_IP_H
#define IMS_IP_H

#include <stddef.h>
#include <stdint.h>

struct ims_udp_packet {
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t *payload;
    size_t payload_len;
};

int ims_ip_parse_udp_ipv4(const uint8_t *packet,
                          size_t packet_len,
                          struct ims_udp_packet *out);
int ims_ip_build_udp_ipv4(uint8_t *out,
                          size_t out_len,
                          const uint8_t src_ip[4],
                          const uint8_t dst_ip[4],
                          uint16_t src_port,
                          uint16_t dst_port,
                          const uint8_t *payload,
                          size_t payload_len);

#endif
