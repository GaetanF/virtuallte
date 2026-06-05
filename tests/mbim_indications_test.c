#include "../src/mbim_frontend/mbim_indications.h"
#include "../src/mbim_frontend/mbim_protocol.h"
#include "../src/modem_state/modem_state.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

struct capture {
    int count;
    uint8_t data[512];
    uint32_t len;
};

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool capture_enqueue(void *user, const uint8_t *data, uint32_t len)
{
    struct capture *c = user;
    assert(len <= sizeof(c->data));
    c->count++;
    c->len = len;
    memcpy(c->data, data, len);
    return true;
}

static const uint8_t *assert_indication(struct capture *c,
                                        const uint8_t *uuid,
                                        uint32_t cid,
                                        uint32_t payload_len)
{
    assert(c->count == 1);
    assert(c->len == 44 + payload_len);
    assert(le32(c->data + 0) == MBIM_INDICATE_STATUS_MSG);
    assert(le32(c->data + 4) == c->len);
    assert(le32(c->data + 12) == 1);
    assert(!memcmp(c->data + 20, uuid, 16));
    assert(le32(c->data + 36) == cid);
    assert(le32(c->data + 40) == payload_len);
    return c->data + 44;
}

static void test_sms_store_status(void)
{
    struct capture c = {0};
    const uint8_t *p;

    assert(mbim_indications_emit_sms_message_store_status(capture_enqueue, &c, 123));
    p = assert_indication(&c, UUID_SMS, MBIM_CID_SMS_MESSAGE_STORE_STATUS, 8);
    assert(le32(p + 0) == MBIM_SMS_STATUS_FLAG_NEW_MESSAGE);
    assert(le32(p + 4) == 123);
}

static void test_packet_service_attached(void)
{
    struct capture c = {0};
    const uint8_t *p;

    assert(mbim_indications_emit_packet_service_attached(capture_enqueue, &c));
    p = assert_indication(&c, UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, 28);
    assert(le32(p + 0) == 0);
    assert(le32(p + 4) == 2);
    assert(le32(p + 8) == 0x20);
    assert(le32(p + 12) == 50000000);
    assert(le32(p + 20) == 100000000);
}

static void test_register_home_truncates_operator_fields(void)
{
    struct capture c = {0};
    struct modem_state st;
    const uint8_t *p;

    memset(&st, 0, sizeof(st));
    strcpy(st.oper.plmn, "00101");
    strcpy(st.oper.name, "OperatorNameLongerThanEightAsciiChars");

    assert(mbim_indications_emit_register_state_home(capture_enqueue, &c, &st));
    p = assert_indication(&c, UUID_BASIC_CONNECT, MBIM_CID_REGISTER_STATE, 76);
    assert(le32(p + 4) == 3);
    assert(le32(p + 12) == 0x20);
    assert(le32(p + 20) == 48);
    assert(le32(p + 24) == 10);
    assert(!memcmp(p + 48, "0\0" "0\0" "1\0" "0\0" "1\0", 10));
    assert(le32(p + 28) == 60);
    assert(le32(p + 32) == 16);
    assert(!memcmp(p + 60, "O\0" "p\0" "e\0" "r\0" "a\0" "t\0" "o\0" "r\0", 16));
}

static void test_once_only_stateful_indications(void)
{
    struct mbim_indications_state st;
    struct capture c = {0};

    mbim_indications_reset(&st);
    assert(mbim_indications_emit_radio_state(&st, capture_enqueue, &c));
    assert_indication(&c, UUID_BASIC_CONNECT, MBIM_CID_RADIO_STATE, 8);
    assert(!mbim_indications_emit_radio_state(&st, capture_enqueue, &c));
    assert(c.count == 1);
}

int main(void)
{
    test_sms_store_status();
    test_packet_service_attached();
    test_register_home_truncates_operator_fields();
    test_once_only_stateful_indications();
    return 0;
}
