#include "../src/ue_engine/ue_nas_decode.h"
#include "../src/ue_engine/ue_nas_encode.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void test_suci_and_identity_response(void)
{
    uint8_t suci[32];
    uint8_t msg[64];
    int len;

    len = ue_nas_encode_suci(suci, sizeof(suci), "001010000000001", "001", "01");
    assert(len == 13);
    assert(suci[0] == 0x01);
    assert(suci[1] == 0x00);
    assert(suci[2] == 0xf1);
    assert(suci[3] == 0x10);
    assert(suci[4] == 0x00 && suci[5] == 0x00);
    assert(suci[6] == 0x00 && suci[7] == 0x00);
    assert(!memcmp(suci + 8, "\x00\x00\x00\x00\x10", 5));

    assert(ue_nas_encode_suci(suci, 4, "001010000000001", "001", "01") < 0);
    assert(ue_nas_encode_suci(suci, sizeof(suci), "001010000000001", "00", "01") < 0);

    len = ue_nas_encode_identity_response(msg, sizeof(msg),
                                          "001010000000001", "001", "01");
    assert(len > 3);
    assert(msg[0] == NAS_EPD_5GMM);
    assert(msg[1] == NAS_SHT_NOT_PROTECTED);
    assert(msg[2] == NAS_MSG_IDENTITY_REQUEST + 1);
    assert(msg[3] == 0);
    assert(msg[4] == 13);
    assert(!memcmp(msg + 5, suci, 13));
}

static void test_simple_uplink_encoders(void)
{
    uint8_t msg[128];
    uint8_t container[] = {NAS_EPD_5GMM, NAS_SHT_NOT_PROTECTED, NAS_MSG_REGISTRATION_REQUEST};
    uint8_t res[16];
    int len;
    int i;

    for (i = 0; i < 16; i++)
        res[i] = (uint8_t)i;

    len = ue_nas_encode_registration_complete(msg, sizeof(msg));
    assert(len == 3);
    assert(msg[0] == NAS_EPD_5GMM);
    assert(msg[1] == NAS_SHT_NOT_PROTECTED);
    assert(msg[2] == NAS_MSG_REGISTRATION_COMPLETE);

    len = ue_nas_encode_auth_response(msg, sizeof(msg), res, sizeof(res));
    assert(len == 21);
    assert(msg[0] == NAS_EPD_5GMM);
    assert(msg[2] == NAS_MSG_AUTHENTICATION_RESPONSE);
    assert(msg[3] == 0x2d);
    assert(msg[4] == sizeof(res));
    assert(!memcmp(msg + 5, res, sizeof(res)));

    len = ue_nas_encode_security_mode_complete(msg, sizeof(msg),
                                               container, sizeof(container));
    assert(len == 9);
    assert(msg[0] == NAS_EPD_5GMM);
    assert(msg[2] == NAS_MSG_SECURITY_MODE_COMPLETE);
    assert(msg[3] == 0x71);
    assert(msg[4] == 0x00 && msg[5] == sizeof(container));
    assert(!memcmp(msg + 6, container, sizeof(container)));

    assert(ue_nas_encode_auth_response(msg, 4, res, sizeof(res)) < 0);
}

static void test_pdu_session_establishment_request(void)
{
    uint8_t msg[256];
    int len;
    uint16_t inner_len;

    len = ue_nas_encode_pdu_session_est_request(msg, sizeof(msg),
                                                7, 9, 1, 1, "internet", 1);
    assert(len > 0);
    assert(msg[0] == NAS_EPD_5GMM);
    assert(msg[1] == NAS_SHT_NOT_PROTECTED);
    assert(msg[2] == 0x67);
    assert((msg[3] & 0x0f) == 0x01);
    inner_len = ((uint16_t)msg[4] << 8) | msg[5];
    assert(inner_len >= 7);
    assert(msg[6] == NAS_EPD_5GSM);
    assert(msg[7] == 7);
    assert(msg[8] == 9);
    assert(msg[9] == NAS_MSG_PDU_SESSION_EST_REQUEST);
    assert(msg[10] == 0xff && msg[11] == 0xff);
    assert(ue_nas_encode_pdu_session_est_request(msg, 8, 7, 9, 1, 1,
                                                 "internet", 1) < 0);
}

static void test_decode_downlink_events(void)
{
    struct ue_nas_event ev;
    const uint8_t auth_req[] = {
        NAS_EPD_5GMM, NAS_SHT_NOT_PROTECTED, NAS_MSG_AUTHENTICATION_REQUEST,
        0x01, 0x02, 0xaa, 0xbb,
        0x21, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        0x20, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
    };
    const uint8_t sm_accept[] = {NAS_EPD_5GSM, 5, 6, NAS_MSG_PDU_SESSION_EST_ACCEPT};
    const uint8_t dl_transport[] = {
        NAS_EPD_5GMM, NAS_SHT_NOT_PROTECTED, NAS_MSG_DL_NAS_TRANSPORT,
        0x01, 0x00, sizeof(sm_accept),
        NAS_EPD_5GSM, 5, 6, NAS_MSG_PDU_SESSION_EST_ACCEPT,
        0x12, 5
    };
    const uint8_t reg_reject[] = {
        NAS_EPD_5GMM, NAS_SHT_NOT_PROTECTED, NAS_MSG_REGISTRATION_REJECT, 0x0b
    };

    memset(&ev, 0, sizeof(ev));
    assert(ue_nas_decode_event(auth_req, sizeof(auth_req), &ev) == 0);
    assert(ev.type == UE_NAS_EVENT_AUTHENTICATION_REQUEST);
    assert(ev.has_ngksi && ev.ngksi == 1);
    assert(ev.has_auth_abba && ev.auth_abba_len == 2);
    assert(ev.auth_abba[0] == 0xaa && ev.auth_abba[1] == 0xbb);
    assert(ev.has_auth_rand && ev.auth_rand[15] == 15);
    assert(ev.has_auth_autn && ev.auth_autn[0] == 15 && ev.auth_autn[15] == 0);

    memset(&ev, 0, sizeof(ev));
    assert(ue_nas_decode_event(dl_transport, sizeof(dl_transport), &ev) == 0);
    assert(ev.type == UE_NAS_EVENT_PDU_SESSION_EST_ACCEPT);
    assert(ev.psi == 5 && ev.pti == 6);

    memset(&ev, 0, sizeof(ev));
    assert(ue_nas_decode_inner_sm(sm_accept, sizeof(sm_accept), &ev) == 0);
    assert(ev.type == UE_NAS_EVENT_PDU_SESSION_EST_ACCEPT);
    assert(ev.psi == 5 && ev.pti == 6);

    memset(&ev, 0, sizeof(ev));
    assert(ue_nas_decode_event(reg_reject, sizeof(reg_reject), &ev) == 0);
    assert(ev.type == UE_NAS_EVENT_REGISTRATION_REJECT);
    assert(ev.mm_cause == 0x0b);
}

int main(void)
{
    test_suci_and_identity_response();
    test_simple_uplink_encoders();
    test_pdu_session_establishment_request();
    test_decode_downlink_events();
    return 0;
}
