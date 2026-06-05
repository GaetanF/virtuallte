#include "../src/ims_service/ims_ip.h"

#include <assert.h>
#include <string.h>

int main(void)
{
    uint8_t src[4] = {10, 45, 0, 2};
    uint8_t dst[4] = {10, 45, 0, 1};
    const uint8_t payload[] = "REGISTER sip:test SIP/2.0\r\n\r\n";
    uint8_t packet[256];
    struct ims_udp_packet parsed;
    int len;

    len = ims_ip_build_udp_ipv4(packet, sizeof(packet), src, dst, 5062, 5060,
                                payload, sizeof(payload) - 1);
    assert(len > 0);
    assert(ims_ip_parse_udp_ipv4(packet, (size_t)len, &parsed) == 0);
    assert(!memcmp(parsed.src_ip, src, 4));
    assert(!memcmp(parsed.dst_ip, dst, 4));
    assert(parsed.src_port == 5062);
    assert(parsed.dst_port == 5060);
    assert(parsed.payload_len == sizeof(payload) - 1);
    assert(!memcmp(parsed.payload, payload, parsed.payload_len));

    return 0;
}
