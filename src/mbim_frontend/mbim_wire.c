#include "mbim_wire.h"

#include <stdio.h>
#include <string.h>

#include "../common/utils.h"

/* Compile-time guarantees that our packed structs match the umbim layout. */
_Static_assert(sizeof(struct mbim_string) == 8, "mbim_string must be 8 bytes");
_Static_assert(sizeof(struct mbim_basic_connect_subscriber_ready_status) == 32,
               "subscriber_ready_status must be 32 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_provisioned_contexts) == 8,
               "provisioned_contexts must be 8 bytes (umbim)");
/* 60B: includes the trailing providerid (umbim provisioned_contexts_s layout). */
_Static_assert(sizeof(struct mbimprovisionedcontextelement) == 60,
               "mbimprovisionedcontextelement must be 60 bytes (with providerid)");
_Static_assert(sizeof(struct mbim_basic_connect_device_caps) == 64,
               "device_caps must be 64 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_register_state) == 48,
               "register_state must be 48 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_packet_service) == 28,
               "packet_service must be 28 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_connect) == 36,
               "connect must be 36 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_ip_configuration) == 60,
               "ip_configuration must be 60 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_radio_state) == 8,
               "radio_state must be 8 bytes (umbim)");
_Static_assert(sizeof(struct mbim_basic_connect_device_services) == 12,
               "device_services must be 12 bytes (umbim)");
_Static_assert(sizeof(struct mbimdeviceserviceelement) == 32,
               "mbimdeviceserviceelement must be 32 bytes (umbim)");
_Static_assert(sizeof(struct mbimipv4element) == 8,
               "mbimipv4element must be 8 bytes (umbim)");
/* MS Basic Connect Extensions (libmbim + Microsoft docs reference). */
_Static_assert(sizeof(struct mbim_ms_context_v2) == 72,
               "ms_context_v2 must be 72 bytes (Microsoft MBIM_MS_CONTEXT_V2)");
_Static_assert(sizeof(struct mbim_ms_provisioned_contexts_info_v2) == 8,
               "ms_provisioned_contexts_info_v2 must be 8 bytes");
_Static_assert(sizeof(struct mbim_ms_lte_attach_configuration) == 44,
               "ms_lte_attach_configuration must be 44 bytes (libmbim)");
_Static_assert(sizeof(struct mbim_ms_lte_attach_configuration_info) == 8,
               "ms_lte_attach_configuration_info must be 8 bytes (libmbim)");
_Static_assert(sizeof(struct mbim_ms_lte_attach_status) == 40,
               "ms_lte_attach_status must be 40 bytes (libmbim)");
/* SMS service (umbim reference). */
_Static_assert(sizeof(struct mbim_sms_configuration) == 24,
               "sms_configuration must be 24 bytes (umbim)");
_Static_assert(sizeof(struct mbim_sms_read) == 16,
               "sms_read must be 16 bytes (umbim)");
_Static_assert(sizeof(struct mbim_sms_pdu_read_record) == 16,
               "sms_pdu_read_record must be 16 bytes (umbim)");
_Static_assert(sizeof(struct mbim_sms_send) == 4,
               "sms_send must be 4 bytes (umbim)");
_Static_assert(sizeof(struct mbim_sms_message_store_status) == 8,
               "sms_message_store_status must be 8 bytes (umbim)");

/* ========================================================================== */
/* Builder                                                                    */
/* ========================================================================== */

void mbim_wire_init(struct mbim_wire_builder *b, uint8_t *info_buffer, uint32_t cap)
{
    b->buf = info_buffer;
    b->cap = cap;
    b->len = 0;
    b->frame_base = 0;
    b->overflow = false;
}

uint32_t mbim_wire_reserve(struct mbim_wire_builder *b, uint32_t n)
{
    uint32_t off = b->len;

    if (n > b->cap || off > b->cap - n) {
        b->overflow = true;
        LOG_ERR(MBIM, "mbim_wire: reserve(%u) overflow at off=%u cap=%u",
                n, off, b->cap);
        return off;
    }

    if (n)
        memset(&b->buf[off], 0, n);
    b->len += n;
    return off;
}

uint32_t mbim_wire_write_utf16le(uint8_t *dst, const char *src)
{
    uint32_t len = (uint32_t)strlen(src);

    for (uint32_t i = 0; i < len; i++) {
        dst[i * 2] = (uint8_t)src[i];
        dst[i * 2 + 1] = 0;
    }

    return len * 2;
}

bool mbim_wire_append_string(struct mbim_wire_builder *b, const char *ascii,
                             struct mbim_string *out)
{
    uint32_t utf16_len = (uint32_t)strlen(ascii) * 2;
    uint32_t padded = mbim_align4(utf16_len);
    uint32_t off;

    if (utf16_len == 0) {
        out->offset = 0;
        out->length = 0;
        return true;
    }

    off = mbim_wire_reserve(b, padded);
    if (b->overflow) {
        out->offset = 0;
        out->length = 0;
        return false;
    }

    mbim_wire_write_utf16le(&b->buf[off], ascii);

    /* Offset is expressed relative to the current frame (InformationBuffer
     * for top-level structs, element start for ref-struct-array entries). */
    out->offset = off - b->frame_base;
    out->length = utf16_len;
    return true;
}

void mbim_wire_put_string(struct mbim_string *dst, struct mbim_string v)
{
    put_le32(&dst->offset, v.offset);
    put_le32(&dst->length, v.length);
}

bool mbim_wire_finalize(const struct mbim_wire_builder *b, const char *cid_name)
{
    if (b->overflow) {
        LOG_ERR(MBIM, "mbim_wire[%s]: OVERFLOW (len would exceed cap=%u)",
                cid_name, b->cap);
        return false;
    }

    if (b->len > b->cap) {
        LOG_ERR(MBIM, "mbim_wire[%s]: len=%u > cap=%u (inconsistent)",
                cid_name, b->len, b->cap);
        return false;
    }

    LOG_DBG(MBIM, "mbim_wire[%s]: info_len=%u cap=%u (ok)",
            cid_name, b->len, b->cap);
    return true;
}

/* ========================================================================== */
/* Debug helpers                                                              */
/* ========================================================================== */

void mbim_wire_hexdump(const char *label, const uint8_t *buf, uint32_t len)
{
    char line[80];

    LOG_DBG(MBIM, "hexdump[%s] len=%u", label, len);
    for (uint32_t i = 0; i < len; i += 16) {
        int p = snprintf(line, sizeof(line), "  %04x:", i);
        for (uint32_t j = 0; j < 16 && i + j < len; j++)
            p += snprintf(line + p, sizeof(line) - (size_t)p, " %02x", buf[i + j]);
        LOG_DBG(MBIM, "%s", line);
    }
}

void mbim_dump_subscriber_ready_model(uint32_t readystate, const char *imsi,
                                      const char *iccid, uint32_t readyinfo,
                                      uint32_t telcount)
{
    LOG_DBG(MBIM,
            "{\"cid\":\"SUBSCRIBER_READY_STATUS\",\"model\":{"
            "\"readystate\":%u,\"subscriberid\":\"%s\",\"simiccid\":\"%s\","
            "\"readyinfo\":%u,\"telephonenumberscount\":%u}}",
            readystate, imsi, iccid, readyinfo, telcount);
}

void mbim_dump_subscriber_ready_wire(const struct mbim_basic_connect_subscriber_ready_status *s,
                                     uint32_t info_len, uint32_t total_msg_len)
{
    LOG_DBG(MBIM,
            "{\"cid\":\"SUBSCRIBER_READY_STATUS\",\"wire\":{"
            "\"fixed\":32,"
            "\"readystate\":%u,"
            "\"subscriberid\":{\"off\":%u,\"len\":%u},"
            "\"simiccid\":{\"off\":%u,\"len\":%u},"
            "\"readyinfo\":%u,\"telephonenumberscount\":%u,"
            "\"info_len\":%u,\"total_msg_len\":%u}}",
            get_le32(&s->readystate),
            get_le32(&s->subscriberid.offset), get_le32(&s->subscriberid.length),
            get_le32(&s->simiccid.offset), get_le32(&s->simiccid.length),
            get_le32(&s->readyinfo), get_le32(&s->telephonenumberscount),
            info_len, total_msg_len);
}

void mbim_dump_provisioned_model(uint32_t count, uint32_t contextid,
                                 const char *contexttype, const char *apn)
{
    LOG_DBG(MBIM,
            "{\"cid\":\"PROVISIONED_CONTEXTS\",\"model\":{"
            "\"count\":%u,\"context\":{\"contextid\":%u,"
            "\"contexttype\":\"%s\",\"accessstring\":\"%s\"}}}",
            count, contextid, contexttype, apn);
}

void mbim_dump_provisioned_wire(uint32_t count, uint32_t elem_off,
                                uint32_t elem_size,
                                const struct mbimprovisionedcontextelement *el,
                                uint32_t info_len, uint32_t total_msg_len)
{
    LOG_DBG(MBIM,
            "{\"cid\":\"PROVISIONED_CONTEXTS\",\"wire\":{"
            "\"count\":%u,"
            "\"reflist\":[{\"off\":%u,\"size\":%u}],"
            "\"element\":{\"base\":%u,\"contextid\":%u,"
            "\"accessstring\":{\"off\":%u,\"len\":%u}},"
            "\"info_len\":%u,\"total_msg_len\":%u}}",
            count, elem_off, elem_size, elem_off,
            get_le32(&el->contextid),
            get_le32(&el->accessstring.offset), get_le32(&el->accessstring.length),
            info_len, total_msg_len);
}
