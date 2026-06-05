#include "mbim_indications.h"

#include <stdio.h>
#include <string.h>

#include "../common/log.h"
#include "../common/utils.h"
#include "../modem_state/modem_state.h"
#include "mbim_protocol.h"
#include "mbim_wire.h"

/* Write src as UTF-16LE into dst, at most `cap` bytes (truncates). Returns the
 * number of bytes written. */
static uint32_t write_utf16le_ascii(uint8_t *dst, const char *src, uint32_t cap)
{
    uint32_t n = 0;

    for (const char *p = src; *p && n + 2 <= cap; p++) {
        dst[n++] = (uint8_t)*p;
        dst[n++] = 0;
    }
    return n;
}

static bool queue_indication_uuid_cid(mbim_indications_enqueue_fn enqueue,
                                      void *user,
                                      const uint8_t *service_id,
                                      uint32_t cid,
                                      const uint8_t *payload,
                                      uint32_t payload_len)
{
    uint8_t ind[512];
    uint32_t total_len = 44 + payload_len;

    if (total_len > sizeof(ind)) {
        LOG_ERR(MBIM, "mbim indication too large cid=%u len=%u", cid, total_len);
        return false;
    }

    memset(ind, 0, total_len);
    put_le32(&ind[0], MBIM_INDICATE_STATUS_MSG);
    put_le32(&ind[4], total_len);
    put_le32(&ind[8], 0);
    put_le32(&ind[12], 1);
    put_le32(&ind[16], 0);
    memcpy(&ind[20], service_id, 16);
    put_le32(&ind[36], cid);
    put_le32(&ind[40], payload_len);

    if (payload_len)
        memcpy(&ind[44], payload, payload_len);

    return enqueue(user, ind, total_len);
}

static void log_packet_service_payload(const char *phase, const uint8_t *payload)
{
    uint32_t nw_error = get_le32(&payload[0]);
    uint32_t state = get_le32(&payload[4]);
    uint32_t data_class = get_le32(&payload[8]);
    uint32_t ul_low = get_le32(&payload[12]);
    uint32_t ul_high = get_le32(&payload[16]);
    uint32_t dl_low = get_le32(&payload[20]);
    uint32_t dl_high = get_le32(&payload[24]);

    LOG_DBG(MBIM,
            "PACKET_SERVICE %s payload nw_error=%u state=%u data_class=0x%x ul=%u:%u dl=%u:%u",
            phase, nw_error, state, data_class, ul_high, ul_low, dl_high, dl_low);
    LOG_TRC(MBIM,
            "PACKET_SERVICE %s raw %08x %08x %08x %08x %08x %08x %08x",
            phase,
            nw_error, state, data_class, ul_low, ul_high, dl_low, dl_high);
}

void mbim_indications_reset(struct mbim_indications_state *st)
{
    memset(st, 0, sizeof(*st));
}

bool mbim_indications_emit_sms_configuration(struct mbim_indications_state *st,
                                             mbim_indications_enqueue_fn enqueue,
                                             void *user)
{
    (void)enqueue;
    (void)user;
    if (st->sms_cfg_sent)
        return false;
    LOG_DBG(MBIM, "skip MBIM_SMS_CONFIGURATION indication (SMS not implemented)");
    st->sms_cfg_sent = true;
    return true;
}

bool mbim_indications_emit_sms_read(mbim_indications_enqueue_fn enqueue,
                                    void *user,
                                    const uint8_t *info, uint32_t info_len)
{
    if (!info || info_len == 0)
        return false;
    if (!queue_indication_uuid_cid(enqueue, user, UUID_SMS,
                                   MBIM_CID_SMS_READ, info, info_len))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_SMS_READ indication info_len=%u", info_len);
    return true;
}

bool mbim_indications_emit_sms_message_store_status(
    mbim_indications_enqueue_fn enqueue,
    void *user,
    uint32_t message_index)
{
    uint8_t payload[8];

    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], MBIM_SMS_STATUS_FLAG_NEW_MESSAGE);  /* 0x02, NOT 0x01 (=store full) */
    put_le32(&payload[4], message_index);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_SMS,
                                   MBIM_CID_SMS_MESSAGE_STORE_STATUS,
                                   payload, sizeof(payload)))
        return false;

    LOG_DBG(MBIM, "emitted MBIM_SMS_MESSAGE_STORE_STATUS indication index=%u",
            message_index);
    return true;
}

bool mbim_indications_emit_packet_service(struct mbim_indications_state *st,
                                          mbim_indications_enqueue_fn enqueue,
                                          void *user)
{
    uint8_t payload[16];
    if (st->packet_service_sent)
        return false;

    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 20);
    put_le32(&payload[8], 0);
    put_le32(&payload[12], 0);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, 10, payload, sizeof(payload)))
        return false;

    st->packet_service_sent = true;
    LOG_DBG(MBIM, "emitted MBIM_PACKET_SERVICE indication");
    LOG_DBG(MBIM, "emit indication type=%d", 10);
    return true;
}

bool mbim_indications_emit_packet_service_attaching(mbim_indications_enqueue_fn enqueue,
                                                      void *user)
{
    uint8_t payload[28];
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 1);
    put_le32(&payload[8], 0);
    put_le32(&payload[12], 0);
    put_le32(&payload[16], 0);
    put_le32(&payload[20], 0);
    put_le32(&payload[24], 0);

    log_packet_service_payload("attaching", payload);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, payload, sizeof(payload))) {
        LOG_WRN(MBIM, "failed to queue MBIM_PACKET_SERVICE attached indication");
        return false;
    }
    LOG_DBG(MBIM, "emitted MBIM_PACKET_SERVICE attaching indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_PACKET_SERVICE);
    return true;
}

bool mbim_indications_emit_packet_service_attached(mbim_indications_enqueue_fn enqueue,
                                                      void *user)
{
    uint8_t payload[28];
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 2);
    put_le32(&payload[8], 0x20);
    put_le32(&payload[12], 50000000);
    put_le32(&payload[16], 0);
    put_le32(&payload[20], 100000000);
    put_le32(&payload[24], 0);

    log_packet_service_payload("attached", payload);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, payload, sizeof(payload)))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_PACKET_SERVICE attached indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_PACKET_SERVICE);
    return true;
}

bool mbim_indications_emit_packet_service_detached(mbim_indications_enqueue_fn enqueue,
                                                     void *user)
{
    uint8_t payload[28];
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 0);
    put_le32(&payload[8], 0);
    put_le32(&payload[12], 0);
    put_le32(&payload[16], 0);
    put_le32(&payload[20], 0);
    put_le32(&payload[24], 0);

    log_packet_service_payload("detached", payload);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_PACKET_SERVICE, payload, sizeof(payload)))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_PACKET_SERVICE detached indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_PACKET_SERVICE);
    return true;
}

bool mbim_indications_emit_register_state_searching(mbim_indications_enqueue_fn enqueue,
                                                      void *user)
{
    uint8_t payload[48];
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 2);
    put_le32(&payload[8], 1);
    put_le32(&payload[12], 0);
    put_le32(&payload[16], 1);
    put_le32(&payload[44], 2);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_REGISTER_STATE, payload, sizeof(payload)))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_REGISTER_STATE searching indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_REGISTER_STATE);
    return true;
}

bool mbim_indications_emit_register_state_deregistered(mbim_indications_enqueue_fn enqueue,
                                                        void *user)
{
    uint8_t payload[48];
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 1);
    put_le32(&payload[8], 1);
    put_le32(&payload[12], 0);
    put_le32(&payload[16], 1);
    put_le32(&payload[44], 2);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_REGISTER_STATE, payload, sizeof(payload)))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_REGISTER_STATE deregistered indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_REGISTER_STATE);
    return true;
}

bool mbim_indications_emit_register_state_home(mbim_indications_enqueue_fn enqueue,
                                                 void *user,
                                                 const struct modem_state *state)
{
    uint8_t payload[76];
    uint32_t plmn_len;
    uint32_t name_len;

    if (!state)
        return false;

    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 3);
    put_le32(&payload[8], 1);
    put_le32(&payload[12], 0x20);
    put_le32(&payload[16], 1);
    put_le32(&payload[20], 48);
    plmn_len = write_utf16le_ascii(&payload[48], state->oper.plmn, 12); /* [48..59] */
    put_le32(&payload[24], plmn_len);
    put_le32(&payload[28], 60);
    name_len = write_utf16le_ascii(&payload[60], state->oper.name, 16); /* [60..75] */
    put_le32(&payload[32], name_len);
    put_le32(&payload[44], 2);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_REGISTER_STATE, payload, sizeof(payload)))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_REGISTER_STATE home indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_REGISTER_STATE);
    LOG_DBG(MBIM, "REGISTER_STATE indication registered=%s", "yes");
    return true;
}

bool mbim_indications_emit_register_state(struct mbim_indications_state *st,
                                          mbim_indications_enqueue_fn enqueue,
                                          void *user)
{
    uint8_t payload[24];
    if (st->register_state_sent)
        return false;
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 1);
    put_le32(&payload[4], 1);
    put_le32(&payload[8], 20);
    put_le32(&payload[12], 1);
    put_le32(&payload[16], 0);
    put_le32(&payload[20], 0);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, 9, payload, sizeof(payload)))
        return false;
    st->register_state_sent = true;
    LOG_DBG(MBIM, "emitted MBIM_REGISTER_STATE indication");
    LOG_DBG(MBIM, "emit indication type=%d", 9);
    LOG_DBG(MBIM, "REGISTER_STATE indication registered=%s", "yes");
    return true;
}

bool mbim_indications_emit_radio_state(struct mbim_indications_state *st,
                                       mbim_indications_enqueue_fn enqueue,
                                       void *user)
{
    uint8_t payload[8];
    if (st->radio_state_sent)
        return false;
    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 1);
    put_le32(&payload[4], 1);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, 3, payload, sizeof(payload)))
        return false;
    st->radio_state_sent = true;
    LOG_DBG(MBIM, "emitted MBIM_RADIO_STATE indication");
    LOG_DBG(MBIM, "emit indication type=%d", 3);
    return true;
}

bool mbim_indications_emit_connect(mbim_indications_enqueue_fn enqueue,
                                   void *user)
{
    (void)enqueue;
    (void)user;
    LOG_DBG(MBIM, "MBIM_CONNECT spontaneous indication disabled");
    return true;
    /*uint8_t payload[36];
    static const uint8_t uuid_context_type_internet[16] = {
        0x7e,0x5e,0x2a,0x7e,0x4e,0x6f,0x72,0x72,
        0x73,0x6b,0x65,0x6e,0x7e,0x5e,0x2a,0x7e
    };

    memset(payload, 0, sizeof(payload));
    put_le32(&payload[0], 0);
    put_le32(&payload[4], 3);
    put_le32(&payload[8], 0);
    put_le32(&payload[12], 1);
    memcpy(&payload[16], uuid_context_type_internet, 16);
    put_le32(&payload[32], 0);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT, MBIM_CID_CONNECT, payload, sizeof(payload)))
        return false;
    LOG_DBG(MBIM, "emitted MBIM_CONNECT indication");
    LOG_DBG(MBIM, "emit indication type=%d", MBIM_CID_CONNECT);
    return true;*/
}

bool mbim_indications_emit_lte_attach_status(mbim_indications_enqueue_fn enqueue,
                                             void *user,
                                             const struct modem_state *state)
{
    uint8_t payload[256];
    const char *apn = (state && state->apn[0]) ? state->apn : "internet";
    uint32_t attach_state = (state && state->packet_attached) ? 1u : 0u; /* Attached:Detached */
    const char *access = attach_state ? apn : "";
    struct mbim_wire_builder b;
    struct mbim_ms_lte_attach_status *s;
    struct mbim_string acc_ref, usr_ref, pwd_ref;
    uint32_t info_len;

    /* Same compliant 40B MS_LTE_ATTACH_STATUS layout as the query handler. */
    memset(payload, 0, sizeof(payload));
    mbim_wire_init(&b, payload, sizeof(payload));
    s = (struct mbim_ms_lte_attach_status *)b.buf;
    mbim_wire_reserve(&b, sizeof(*s));
    mbim_wire_append_string(&b, access, &acc_ref);
    mbim_wire_append_string(&b, "", &usr_ref);
    mbim_wire_append_string(&b, "", &pwd_ref);

    put_le32(&s->lteattachstate, attach_state);
    put_le32(&s->iptype, 1);                         /* IPV4 */
    mbim_wire_put_string(&s->accessstring, acc_ref);
    mbim_wire_put_string(&s->username, usr_ref);
    mbim_wire_put_string(&s->password, pwd_ref);
    put_le32(&s->compression, 0);
    put_le32(&s->authprotocol, 0);
    info_len = mbim_wire_len(&b);

    LOG_DBG(MBIM, "LTE_ATTACH_STATUS ind state=%u apn='%s' info_len=%u",
            attach_state, access, info_len);

    if (!queue_indication_uuid_cid(enqueue, user, UUID_BASIC_CONNECT_EXTENSIONS,
                                   MBIM_EXT_CID_LTE_ATTACH_STATUS, payload, info_len))
        return false;

    LOG_DBG(MBIM, "emitted MBIM_LTE_ATTACH_STATUS indication state=%u apn='%s'",
            attach_state, access);
    return true;
}
