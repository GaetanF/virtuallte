#include "mbim_handlers.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../common/log.h"
#include "../common/utils.h"
#include "../modem_state/modem_state.h"
#include "mbim_protocol.h"
#include "mbim_wire.h"

/* InformationBuffer capacity = response buffer (last_mbim_resp[4096]) minus the
 * 48-byte MBIM_COMMAND_DONE header. */
#define MBIM_INFOBUF_CAP (4096u - 48u)

static bool uuid_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 16) == 0;
}

struct mbim_bce_state {
    char attach_apn[64];
    bool attach_apn_set;
};

static struct mbim_bce_state g_bce_state = {
    .attach_apn = "internet",
    .attach_apn_set = false,
};

static uint32_t utf16le_ascii_to_cstr(char *dst, uint32_t dst_len,
                                      const uint8_t *src, uint32_t src_len)
{
    uint32_t n = 0;

    if (!dst || dst_len == 0 || !src)
        return 0;

    for (uint32_t i = 0; i + 1 < src_len && n + 1 < dst_len; i += 2) {
        uint8_t c = src[i];
        if (c == 0)
            break;
        dst[n++] = (char)c;
    }
    dst[n] = '\0';
    return n;
}

static void init_command_done(uint8_t *resp, const uint8_t *cmd, uint32_t tid, uint32_t cid)
{
    memset(resp, 0, 4096);
    put_le32(&resp[0], MBIM_COMMAND_DONE);
    put_le32(&resp[8], tid);
    put_le32(&resp[12], 1);
    put_le32(&resp[16], 0);
    memcpy(&resp[20], &cmd[20], 16);
    put_le32(&resp[36], cid);
    put_le32(&resp[40], MBIM_STATUS_SUCCESS);
}

/* ---- Internal SMS store (incoming SMS over IMS, read by the host) ---- */

#define MBIM_SMS_STORE_MAX 8
#define MBIM_SMS_PDU_MAX   256

struct mbim_sms_store_entry {
    bool used;
    bool unread;     /* New (true) vs Old (false); cleared only on host read */
    bool notified;   /* SMS_READ indication already pushed for this message */
    uint32_t index;
    uint8_t pdu[MBIM_SMS_PDU_MAX];
    uint32_t pdu_len;
};
static struct mbim_sms_store_entry g_sms_store[MBIM_SMS_STORE_MAX];
static uint32_t g_sms_next_index = 1;

bool mbim_handlers_sms_store_append(const uint8_t *pdu, uint32_t pdu_len,
                                    uint32_t *message_index)
{
    int slot = -1;

    if (!pdu || pdu_len == 0 || pdu_len > MBIM_SMS_PDU_MAX)
        return false;

    for (int i = 0; i < MBIM_SMS_STORE_MAX; i++) {
        if (!g_sms_store[i].used) {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        slot = 0;   /* store full: overwrite oldest slot */

    g_sms_store[slot].used = true;
    g_sms_store[slot].unread = true;
    g_sms_store[slot].notified = false;
    g_sms_store[slot].index = g_sms_next_index++;
    memcpy(g_sms_store[slot].pdu, pdu, pdu_len);
    g_sms_store[slot].pdu_len = pdu_len;
    if (message_index)
        *message_index = g_sms_store[slot].index;
    LOG_DBG(MBIM, "SMS store append index=%u len=%u", g_sms_store[slot].index, pdu_len);
    return true;
}

bool mbim_handlers_sms_store_has_unread(uint32_t *message_index)
{
    for (int i = 0; i < MBIM_SMS_STORE_MAX; i++) {
        if (g_sms_store[i].used && g_sms_store[i].unread) {
            if (message_index)
                *message_index = g_sms_store[i].index;
            return true;
        }
    }
    return false;
}

static void sms_store_delete(uint32_t index)
{
    for (int i = 0; i < MBIM_SMS_STORE_MAX; i++) {
        if (g_sms_store[i].used && (index == 0 || g_sms_store[i].index == index))
            memset(&g_sms_store[i], 0, sizeof(g_sms_store[i]));
    }
}

/*
 * Extract the SMS PDU from an MBIM_SET_SMS_SEND InformationBuffer.
 *
 * Layout (PDU format), confirmed on the wire:
 *   ib[0..3]  Format         (UINT32, 0 = PDU)
 *   ib[4..7]  PduDataOffset  (UINT32, relative to the SMS_SEND_PDU record = ib+4)
 *   ib[8..11] PduDataSize    (UINT32)
 *   ib[4+off .. +size]  PduData = 27.005 PDU [SCA-len][SCA][TPDU]
 * Returns PduData as-is (the SCA is stripped later when building RP-DATA).
 */
static bool sms_extract_send_pdu(const uint8_t *ib, uint32_t ib_len,
                                 uint8_t *out, uint32_t out_cap,
                                 uint32_t *out_len)
{
    uint32_t format;
    uint32_t off;
    uint32_t size;
    uint64_t abs_off;

    if (out_len)
        *out_len = 0;
    if (!ib || !out || !out_len || ib_len < 12)
        return false;

    format = get_le32(&ib[0]);
    if (format != 0)            /* 0 = MBIMSmsFormatPdu (CDMA not supported) */
        return false;

    off = get_le32(&ib[4]);     /* offset relative to the record start (ib+4) */
    size = get_le32(&ib[8]);    /* PduDataSize */
    abs_off = (uint64_t)4 + off;
    if (size == 0 || size > out_cap || abs_off + size > ib_len)
        return false;

    memcpy(out, &ib[abs_off], size);
    *out_len = size;
    return true;
}

enum sms_read_mode {
    SMS_READ_QUERY,      /* host read (Flag=All): all stored, mark read (New->Old) */
    SMS_READ_QUERY_NEW,  /* host read (Flag=New): only unread, mark read           */
    SMS_READ_NOTIFY,     /* unsolicited push: not-yet-notified msgs, keep them New */
};

static bool sms_entry_included(const struct mbim_sms_store_entry *e,
                               enum sms_read_mode mode)
{
    if (!e->used)
        return false;
    switch (mode) {
    case SMS_READ_QUERY_NEW: return e->unread;     /* only new/unread */
    case SMS_READ_NOTIFY:    return !e->notified;  /* not yet pushed  */
    case SMS_READ_QUERY:
    default:                 return true;          /* everything      */
    }
}

/*
 * Build an MBIM_SMS_READ_INFO into `out` from the stored messages.
 *  - QUERY  (host SMS_READ): include all stored; status = New/Old per `unread`;
 *    mark them read (unread=false) so a re-read shows Old.
 *  - NOTIFY (unsolicited SMS_READ indication): include messages not yet pushed;
 *    status = New; mark `notified` only — the message stays New until the host
 *    actually reads it via a query (so it doesn't get stuck New, nor flip to Old
 *    before the host reads it).
 * Returns the SMS_READ_INFO length, or 0 on overflow.
 */
static uint32_t sms_build_read_info(uint8_t *out, uint32_t out_cap,
                                    enum sms_read_mode mode)
{
    struct mbim_wire_builder b;
    uint32_t count = 0;
    uint32_t reflist_off;
    uint32_t written = 0;
    uint32_t info_len;

    for (int i = 0; i < MBIM_SMS_STORE_MAX; i++)
        if (sms_entry_included(&g_sms_store[i], mode))
            count++;

    mbim_wire_init(&b, out, out_cap);
    /*
     * MBIM_SMS_READ_INFO: Format(4) + ElementCount(4), then the OL_PAIR list
     * (one {offset,size} per message) INLINE at offset 8 — there is NO
     * pdumessages/cdmamessages field. (The earlier 16-byte header shifted the
     * ref list and made ref[0] = the bogus pair (16,0), so the host couldn't
     * display the messages.)
     */
    mbim_wire_reserve(&b, 8);
    reflist_off = mbim_wire_reserve(&b, 8 * count);

    for (int i = 0; i < MBIM_SMS_STORE_MAX && written < count; i++) {
        struct mbim_sms_pdu_read_record *rec;
        struct mbim_string *ref;
        struct mbim_string pdu_ref;
        uint32_t rec_off;
        uint32_t pdu_off;
        uint32_t pdu_padded;
        uint32_t rec_size;

        if (!sms_entry_included(&g_sms_store[i], mode))
            continue;

        rec_off = mbim_wire_reserve(&b, sizeof(*rec));
        rec = (struct mbim_sms_pdu_read_record *)&b.buf[rec_off];
        b.frame_base = rec_off;
        pdu_padded = mbim_align4(g_sms_store[i].pdu_len);
        pdu_off = mbim_wire_reserve(&b, pdu_padded);
        if (!b.overflow)
            memcpy(&b.buf[pdu_off], g_sms_store[i].pdu, g_sms_store[i].pdu_len);
        pdu_ref.offset = pdu_off - rec_off;
        pdu_ref.length = g_sms_store[i].pdu_len;
        b.frame_base = 0;

        put_le32(&rec->messageindex, g_sms_store[i].index);
        put_le32(&rec->messagestatus, g_sms_store[i].unread ? 0 : 1);
        mbim_wire_put_string(&rec->pdudata, pdu_ref);

        rec_size = mbim_wire_len(&b) - rec_off;
        ref = (struct mbim_string *)&b.buf[reflist_off + written * 8];
        mbim_wire_put_string(ref, (struct mbim_string){ rec_off, rec_size });
        if (mode == SMS_READ_NOTIFY)
            g_sms_store[i].notified = true;  /* pushed; stays New until read */
        else
            g_sms_store[i].unread = false;   /* host read it -> Old */
        written++;
    }

    put_le32(&b.buf[0], 0);          /* Format = PDU */
    put_le32(&b.buf[4], written);    /* ElementCount */
    info_len = mbim_wire_len(&b);
    if (!mbim_wire_finalize(&b, "SMS_READ_INFO"))
        return 0;
    return info_len;
}

/*
 * Build an SMS_READ_INFO carrying the not-yet-pushed messages for an unsolicited
 * SMS_READ indication (status New, kept New). Returns true if ≥1 message included.
 */
bool mbim_handlers_build_sms_read_indication(uint8_t *out, uint32_t out_cap,
                                             uint32_t *out_len)
{
    bool any = false;
    uint32_t len;
    int i;

    if (out_len)
        *out_len = 0;
    for (i = 0; i < MBIM_SMS_STORE_MAX; i++) {
        if (g_sms_store[i].used && !g_sms_store[i].notified) {
            any = true;
            break;
        }
    }
    if (!any)
        return false;

    len = sms_build_read_info(out, out_cap, SMS_READ_NOTIFY);
    if (out_len)
        *out_len = len;
    return len > 0;
}

static bool handle_vendor_command(const uint8_t *cmd,
                                  uint32_t cmd_len,
                                  struct modem_state *state,
                                  const struct mbim_handler_actions *actions,
                                  uint32_t tid,
                                  uint32_t cid,
                                  uint32_t ib_len,
                                  uint32_t cmd_type,
                                  uint8_t *resp,
                                  uint32_t *resp_len,
                                  struct mbim_vendor_event *vendor_event)
{
    uint32_t vendor_payload_len = 0;
    bool is_ext_qmux;
    bool is_basic_ext;
    bool is_sms;
    bool ctl_sync_match = false;
    const uint8_t *q = NULL;

    (void)cmd_type;

    is_ext_qmux = uuid_eq(&cmd[20], UUID_EXT_QMUX);
    is_basic_ext = uuid_eq(&cmd[20], UUID_BASIC_CONNECT_EXTENSIONS);
    is_sms = uuid_eq(&cmd[20], UUID_SMS);
    if (is_ext_qmux) {
        if (ib_len > 0 && (48u + ib_len) <= cmd_len) {
            q = &cmd[48];
            vendor_payload_len = ib_len;
        } else if (cmd_len > 48) {
            /* fallback only if ib_len is inconsistent */
            q = &cmd[48];
            vendor_payload_len = cmd_len - 48;
        }
    } else if (cmd_len > 48) {
        vendor_payload_len = cmd_len - 48;
    }

    if (vendor_event)
        vendor_event->type = MBIM_VENDOR_EVENT_NONE;

    if (is_ext_qmux) {
        LOG_DBG(QMI, "vendor QMUX cmd: tid=%u cid=%u cmd_type=%u payload_len=%u",
                tid, cid, cmd_type, vendor_payload_len);
        LOG_DBG(QMI, "QMUX parse base: ib_len=%u payload_len=%u",
                ib_len, vendor_payload_len);
    }

    if (is_ext_qmux && q && vendor_payload_len >= 12) {
        LOG_DBG(QMI, "QMUX req head q[0..11]=%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[8], q[9], q[10], q[11]);

        if (q[0] == 0x01 && q[1] == 0x0b &&
            q[2] == 0x00 && q[3] == 0x00 &&
            q[4] == 0x00 && q[5] == 0x00 &&
            q[6] == 0x00 &&
            /* q[7] = txn (variable) */
            q[8] == 0x27 && q[9] == 0x00 &&
            q[10] == 0x00 && q[11] == 0x00) {
            ctl_sync_match = true;
            if (vendor_event) {
                vendor_event->type = MBIM_VENDOR_EVENT_QMI_CTL_SYNC;
                vendor_event->tid = tid;
                vendor_event->cid = cid;
                vendor_event->qmi_payload = q;
                vendor_event->qmi_payload_len = vendor_payload_len;
            }
            LOG_DBG(QMI, "vendor QMUX CTL_SYNC matched txn=%u msgid=0x%04x",
                    (unsigned)q[7],
                    (unsigned)((uint16_t)q[8] | ((uint16_t)q[9] << 8)));
            *resp_len = 0;
            return true;
        }
    }

    if (is_ext_qmux) {
        LOG_WRN(QMI, "vendor QMUX CTL_SYNC matched=%s", ctl_sync_match ? "yes" : "no");
        LOG_WRN(QMI, "qmux fallback removed / returning failure");
        init_command_done(resp, cmd, tid, cid);
        put_le32(&resp[4], 48);
        put_le32(&resp[40], 1); /* generic MBIM failure status */
        put_le32(&resp[44], 0);
        *resp_len = 48;
        return true;
    }

    if (is_basic_ext) {
        init_command_done(resp, cmd, tid, cid);

        if (cid == MBIM_EXT_CID_PROVISIONED_CONTEXT_V2) {
            /*
             * MBIM_MS_PROVISIONED_CONTEXTS_INFO_V2 (Microsoft docs): ElementCount
             * + ref-struct-array of MBIM_MS_CONTEXT_V2 (72B element,
             * accessstring offset element-relative). Single enabled context.
             */
            static const uint8_t context_type_internet[16] = {
                0xb4, 0x3f, 0x75, 0x8c, 0xa5, 0x60, 0x4b, 0x46,
                0xb3, 0x5e, 0xc5, 0x86, 0x96, 0x41, 0xfb, 0x54
            };
            struct mbim_wire_builder b;
            struct mbim_ms_provisioned_contexts_info_v2 *hdr;
            struct mbim_ms_context_v2 *el;
            struct mbim_string *ref;
            const char *apn = (state && state->apn[0]) ? state->apn : "internet";
            struct mbim_string apn_ref;
            uint32_t reflist_off, elem_off, elem_size, info_len, total_msg_len;

            mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
            hdr = (struct mbim_ms_provisioned_contexts_info_v2 *)b.buf;
            mbim_wire_reserve(&b, 4);                       /* elementcount  off 0  */
            reflist_off = mbim_wire_reserve(&b, 8);         /* OL_PAIR       off 4  */
            elem_off = mbim_wire_reserve(&b, sizeof(*el));  /* 72B element   off 12 */
            el = (struct mbim_ms_context_v2 *)&b.buf[elem_off];

            b.frame_base = elem_off;                        /* element-relative */
            mbim_wire_append_string(&b, apn, &apn_ref);
            b.frame_base = 0;
            elem_size = mbim_wire_len(&b) - elem_off;

            put_le32(&el->contextid, 1);
            memcpy(el->contexttype, context_type_internet, 16);
            put_le32(&el->iptype, 1);                       /* IPV4 */
            put_le32(&el->enable, 1);                       /* Enabled */
            put_le32(&el->roaming, 6);                      /* AllowAll */
            put_le32(&el->mediatype, 0);                    /* CellularOnly */
            put_le32(&el->source, 0);                       /* Admin */
            mbim_wire_put_string(&el->accessstring, apn_ref);
            /* username/password = {0,0}, compression/auth = 0 (zero-filled) */

            put_le32(&hdr->elementcount, 1);
            ref = (struct mbim_string *)&b.buf[reflist_off];
            mbim_wire_put_string(ref, (struct mbim_string){ elem_off, elem_size });

            info_len = mbim_wire_len(&b);
            total_msg_len = 48 + info_len;
            put_le32(&resp[4], total_msg_len);
            put_le32(&resp[44], info_len);
            *resp_len = total_msg_len;
            mbim_wire_finalize(&b, "MS_PROVISIONED_CONTEXT_V2");
            LOG_DBG(MBIM, "BCE PROVISIONED_CONTEXT_V2 %s apn='%s' info_len=%u",
                    cmd_type == 1 ? "set" : "query", apn, info_len);
            return true;
        }

        if (cid == MBIM_EXT_CID_LTE_ATTACH_CONFIG) {
            /*
             * MS_LTE_ATTACH_CONFIGURATION (libmbim): configurationcount + a
             * ref-struct-array of mbim_ms_lte_attach_configuration (44B each,
             * accessstring offset element-relative). One entry per roaming
             * condition (Home/Partner/NonPartner), same APN.
             */
            struct mbim_wire_builder b;
            struct mbim_ms_lte_attach_configuration_info *hdr;
            const char *apn;
            const uint32_t count = 3;     /* Home, Partner, NonPartner */
            uint32_t reflist_off, info_len, total_msg_len;

            if (cmd_type == 1 && vendor_payload_len >= 8) {
                char apn_tmp[64] = {0};
                uint32_t tail = vendor_payload_len > 64 ? 64 : vendor_payload_len;
                const uint8_t *cand = &cmd[48 + (vendor_payload_len - tail)];

                if (utf16le_ascii_to_cstr(apn_tmp, sizeof(apn_tmp), cand, tail) > 0) {
                    strncpy(g_bce_state.attach_apn, apn_tmp, sizeof(g_bce_state.attach_apn) - 1);
                    g_bce_state.attach_apn[sizeof(g_bce_state.attach_apn) - 1] = '\0';
                    g_bce_state.attach_apn_set = true;
                    LOG_DBG(MBIM, "BCE LTE_ATTACH_CONFIG set attach_apn='%s'", g_bce_state.attach_apn);
                }
            }

            apn = g_bce_state.attach_apn_set ? g_bce_state.attach_apn :
                  (state ? state->apn : "internet");

            mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
            hdr = (struct mbim_ms_lte_attach_configuration_info *)b.buf;
            mbim_wire_reserve(&b, 4);                       /* configurationcount */
            reflist_off = mbim_wire_reserve(&b, 8 * count); /* OL_PAIR per config */

            for (uint32_t i = 0; i < count; i++) {
                struct mbim_ms_lte_attach_configuration *cfg;
                struct mbim_string apn_ref, *ref;
                uint32_t cfg_off = mbim_wire_reserve(&b, sizeof(*cfg));

                cfg = (struct mbim_ms_lte_attach_configuration *)&b.buf[cfg_off];
                b.frame_base = cfg_off;                     /* element-relative */
                mbim_wire_append_string(&b, apn, &apn_ref);
                b.frame_base = 0;

                put_le32(&cfg->iptype, 1);                  /* IPV4 */
                put_le32(&cfg->roaming, i);                 /* Home/Partner/NonPartner */
                put_le32(&cfg->source, 0);                  /* Admin */
                mbim_wire_put_string(&cfg->accessstring, apn_ref);
                /* username/password = {0,0}, compression/auth = 0 (zero-filled) */

                ref = (struct mbim_string *)&b.buf[reflist_off + i * 8];
                mbim_wire_put_string(ref,
                    (struct mbim_string){ cfg_off, mbim_wire_len(&b) - cfg_off });
            }

            put_le32(&hdr->configurationcount, count);

            info_len = mbim_wire_len(&b);
            total_msg_len = 48 + info_len;
            put_le32(&resp[4], total_msg_len);
            put_le32(&resp[44], info_len);
            *resp_len = total_msg_len;
            mbim_wire_finalize(&b, "MS_LTE_ATTACH_CONFIG");
            LOG_DBG(MBIM, "BCE LTE_ATTACH_CONFIG %s apn='%s' count=%u info_len=%u",
                    cmd_type == 1 ? "set" : "query", apn, count, info_len);
            return true;
        }

        if (cid == MBIM_EXT_CID_LTE_ATTACH_STATUS) {
            /*
             * MS_LTE_ATTACH_STATUS / "LTE Attach Info" (libmbim): 40B flat
             * struct + DataBuffer (accessstring/username/password, offsets
             * relative to the InformationBuffer).
             */
            struct mbim_wire_builder b;
            struct mbim_ms_lte_attach_status *s;
            const char *apn = g_bce_state.attach_apn_set ? g_bce_state.attach_apn :
                              (state ? state->apn : "internet");
            uint32_t attach_state = (state && state->packet_attached) ? 1u : 0u; /* Attached:Detached */
            const char *access = attach_state ? apn : "";
            struct mbim_string acc_ref, usr_ref, pwd_ref;
            uint32_t info_len, total_msg_len;

            mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
            s = (struct mbim_ms_lte_attach_status *)b.buf;
            mbim_wire_reserve(&b, sizeof(*s));              /* 40B fixed */
            mbim_wire_append_string(&b, access, &acc_ref);
            mbim_wire_append_string(&b, "", &usr_ref);
            mbim_wire_append_string(&b, "", &pwd_ref);

            put_le32(&s->lteattachstate, attach_state);
            put_le32(&s->iptype, 1);                        /* IPV4 */
            mbim_wire_put_string(&s->accessstring, acc_ref);
            mbim_wire_put_string(&s->username, usr_ref);
            mbim_wire_put_string(&s->password, pwd_ref);
            put_le32(&s->compression, 0);
            put_le32(&s->authprotocol, 0);

            info_len = mbim_wire_len(&b);
            total_msg_len = 48 + info_len;
            put_le32(&resp[4], total_msg_len);
            put_le32(&resp[44], info_len);
            *resp_len = total_msg_len;
            mbim_wire_finalize(&b, "MS_LTE_ATTACH_STATUS");
            LOG_DBG(MBIM, "BCE LTE_ATTACH_STATUS state=%u apn='%s' info_len=%u",
                    attach_state, access, info_len);
            return true;
        }

        put_le32(&resp[4], 48);
        put_le32(&resp[44], 0);
        *resp_len = 48;
        return true;
    }

    if (is_sms) {
        init_command_done(resp, cmd, tid, cid);

        if (cid == MBIM_CID_SMS_CONFIGURATION) {
            /* MBIM_SMS_CONFIGURATION_INFO (umbim sms_configuration): 24B fixed
             * + scaddress string. PDU format, store initialized, no SC addr. */
            struct mbim_wire_builder b;
            struct mbim_sms_configuration *c;
            struct mbim_string sca_ref;
            uint32_t info_len;

            mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
            c = (struct mbim_sms_configuration *)b.buf;
            mbim_wire_reserve(&b, sizeof(*c));
            mbim_wire_append_string(&b, "", &sca_ref);  /* no service-centre addr */
            put_le32(&c->smsstoragestate, 1);           /* Initialized */
            put_le32(&c->format, 0);                    /* PDU */
            put_le32(&c->maxmessages, 100);
            put_le32(&c->cdmashortmessagesize, 0);
            mbim_wire_put_string(&c->scaddress, sca_ref);

            info_len = mbim_wire_len(&b);
            put_le32(&resp[4], 48 + info_len);
            put_le32(&resp[44], info_len);
            *resp_len = 48 + info_len;
            mbim_wire_finalize(&b, "SMS_CONFIGURATION");
            LOG_DBG(MBIM, "SMS_CONFIGURATION %s info_len=%u",
                    cmd_type == 1 ? "set" : "query", info_len);
            return true;
        }

        if (cid == MBIM_CID_SMS_READ) {
            /*
             * MBIM_SMS_READ_REQ: Format @ib[0], Flag @ib[4]=cmd[52], Index @ib[8].
             * Honour Flag=New: a host that polls SMS_READ must get each message
             * only once, otherwise it re-receives the whole store on every poll
             * and the inbox keeps duplicating. New -> only unread (then marked
             * Old); anything else -> all stored.
             */
            uint32_t flag = (cmd_len >= 56) ? get_le32(&cmd[52]) : MBIM_SMS_FLAG_ALL;
            enum sms_read_mode mode =
                (flag == MBIM_SMS_FLAG_NEW) ? SMS_READ_QUERY_NEW : SMS_READ_QUERY;
            uint32_t info_len = sms_build_read_info(&resp[48], MBIM_INFOBUF_CAP, mode);
            put_le32(&resp[4], 48 + info_len);
            put_le32(&resp[44], info_len);
            *resp_len = 48 + info_len;
            LOG_DBG(MBIM, "SMS_READ query flag=%u -> info_len=%u", flag, info_len);
            return true;
        }

        if (cid == MBIM_CID_SMS_MESSAGE_STORE_STATUS) {
            /* MBIM_SMS_MESSAGE_STORE_STATUS_INFO (umbim). */
            struct mbim_sms_message_store_status *s =
                (struct mbim_sms_message_store_status *)&resp[48];
            uint32_t msg_index = 0;
            bool has_unread = mbim_handlers_sms_store_has_unread(&msg_index);

            put_le32(&s->flag,
                     has_unread ? MBIM_SMS_STATUS_FLAG_NEW_MESSAGE : MBIM_SMS_STATUS_FLAG_NONE);
            put_le32(&s->messageindex, msg_index);
            put_le32(&resp[4], 48 + (uint32_t)sizeof(*s));
            put_le32(&resp[44], (uint32_t)sizeof(*s));
            *resp_len = 48 + (uint32_t)sizeof(*s);
            LOG_DBG(MBIM, "SMS_MESSAGE_STORE_STATUS unread=%s index=%u",
                    has_unread ? "yes" : "no", msg_index);
            return true;
        }

        if (cid == MBIM_CID_SMS_SEND) {
            /* MBIM_SMS_SEND_INFO (umbim sms_send): send the PDU over IMS only. */
            uint8_t pdu[MBIM_SMS_PDU_MAX];
            uint32_t pdu_len = 0;
            struct mbim_sms_send *s = (struct mbim_sms_send *)&resp[48];
            uint32_t ref = 0;
            bool sent = false;

            if (sms_extract_send_pdu(&cmd[48], vendor_payload_len,
                                     pdu, sizeof(pdu), &pdu_len) &&
                actions && actions->send_sms_ims &&
                actions->send_sms_ims(actions->user, pdu, pdu_len, &ref) == 0)
                sent = true;

            if (!sent) {
                /* COMMAND_DONE with failure status, no InformationBuffer. */
                put_le32(&resp[4], 48);
                put_le32(&resp[40], 1);   /* MBIM_STATUS_FAILURE */
                put_le32(&resp[44], 0);
                *resp_len = 48;
                LOG_WRN(MBIM, "SMS_SEND failed pdu_len=%u ims_registered=%s",
                        pdu_len, (actions && actions->ims_registered) ? "yes" : "no");
                return true;
            }

            put_le32(&s->messagereference, ref);
            put_le32(&resp[4], 48 + (uint32_t)sizeof(*s));
            put_le32(&resp[44], (uint32_t)sizeof(*s));
            *resp_len = 48 + (uint32_t)sizeof(*s);
            LOG_DBG(MBIM, "SMS_SEND -> reference=%u pdu_len=%u", ref, pdu_len);
            return true;
        }

        if (cid == MBIM_CID_SMS_DELETE) {
            uint32_t index = 0;
            if (vendor_payload_len >= 12)
                index = get_le32(&cmd[48 + 8]);
            sms_store_delete(index);
            /* No InformationBuffer in the response. */
            put_le32(&resp[4], 48);
            put_le32(&resp[44], 0);
            *resp_len = 48;
            LOG_DBG(MBIM, "SMS_DELETE index=%u -> success", index);
            return true;
        }

        put_le32(&resp[4], 48);
        put_le32(&resp[44], 0);
        *resp_len = 48;
        return true;
    }

    init_command_done(resp, cmd, tid, cid);
    put_le32(&resp[4], 48 + vendor_payload_len);
    put_le32(&resp[44], vendor_payload_len);

    if (vendor_payload_len > 0)
        memcpy(&resp[48], &cmd[48], vendor_payload_len);

    *resp_len = 48 + vendor_payload_len;
    return true;
}

bool mbim_handlers_handle_command(const uint8_t *cmd,
                                  uint32_t cmd_len,
                                  struct modem_state *state,
                                  const struct mbim_handler_actions *actions,
                                  uint8_t *resp,
                                  uint32_t *resp_len,
                                  struct mbim_vendor_event *vendor_event)
{
    uint32_t tid;
    uint32_t cid;
    uint32_t cmd_type;
    uint32_t ib_len;
    bool is_basic;

    if (!cmd || !resp || !resp_len || cmd_len < 48)
        return false;

    tid = get_le32(&cmd[8]);
    cid = get_le32(&cmd[36]);
    cmd_type = get_le32(&cmd[40]);
    ib_len = get_le32(&cmd[44]);
    is_basic = uuid_eq(&cmd[20], UUID_BASIC_CONNECT);

    if (!is_basic)
        return handle_vendor_command(cmd, cmd_len, state, actions, tid, cid, ib_len, cmd_type,
                                     resp, resp_len, vendor_event);

    LOG_DBG(MBIM, "command tid=%u cid=%u cmd_type=%u ib_len=%u", tid, cid, cmd_type, ib_len);

    init_command_done(resp, cmd, tid, cid);

    if (cid == MBIM_CID_DEVICE_CAPS) {
        LOG_DBG(MBIM, "DEVICE_CAPS query");
        if (cmd_type != 0) {
            put_le32(&resp[4], 48);
            put_le32(&resp[44], 0);
            *resp_len = 48;
            return true;
        } else {
            /*
             * MBIM_DEVICE_CAPS_INFO (struct mbim_basic_connect_device_caps,
             * 64B fixed) + customdataclass/deviceid/firmwareinfo/hardwareinfo
             * appended as UTF-16LE strings (offsets relative to the
             * InformationBuffer, the builder pads each string to 4 bytes).
             */
            struct mbim_wire_builder b;
            struct mbim_basic_connect_device_caps *d;
            const char *custom = "";
            const char *device_id = state->identity.imei;
            const char *fw_info = state->identity.firmware;
            const char *hw_info = state->identity.model;
            struct mbim_string custom_ref, devid_ref, fw_ref, hw_ref;
            uint32_t info_len, total_msg_len;

            mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
            d = (struct mbim_basic_connect_device_caps *)b.buf;
            mbim_wire_reserve(&b, sizeof(*d));            /* fixed 64B */

            mbim_wire_append_string(&b, custom, &custom_ref);
            mbim_wire_append_string(&b, device_id, &devid_ref);
            mbim_wire_append_string(&b, fw_info, &fw_ref);
            mbim_wire_append_string(&b, hw_info, &hw_ref);

            put_le32(&d->devicetype, 2);     /* MBIM_DEVICE_TYPE_EMBEDDED */
            put_le32(&d->cellularclass, 1);  /* GSM */
            put_le32(&d->voiceclass, 1);     /* NO_VOICE / class 1 */
            put_le32(&d->simclass, 2);       /* REMOVABLE */
            put_le32(&d->dataclass, 0x20);   /* LTE */
            /* Advertise SMS send+receive (PDU) only when SMS over IMS is enabled
             * in config; the host gates SMS on this DEVICE_CAPS field. */
            put_le32(&d->smscaps,
                     (actions && actions->sms_enabled && actions->ims_enabled)
                         ? (MBIM_SMS_CAPS_PDU_RECEIVE | MBIM_SMS_CAPS_PDU_SEND)
                         : 0);
            put_le32(&d->controlcaps, 1);    /* REG_MANUAL */
            put_le32(&d->maxsessions, 1);
            mbim_wire_put_string(&d->customdataclass, custom_ref);
            mbim_wire_put_string(&d->deviceid, devid_ref);
            mbim_wire_put_string(&d->firmwareinfo, fw_ref);
            mbim_wire_put_string(&d->hardwareinfo, hw_ref);

            info_len = mbim_wire_len(&b);
            total_msg_len = 48 + info_len;
            put_le32(&resp[4], total_msg_len);
            put_le32(&resp[44], info_len);
            *resp_len = total_msg_len;
            mbim_wire_finalize(&b, "DEVICE_CAPS");
            return true;
        }
    } else if (cid == MBIM_CID_SUBSCRIBER_READY_STATUS) {
        /*
         * MBIM_SUBSCRIBER_READY_STATUS_INFO, umbim layout (32B fixed):
         *   off 0  readystate
         *   off 4  subscriberid { offset, length }
         *   off 12 simiccid     { offset, length }
         *   off 20 readyinfo
         *   off 24 telephonenumberscount
         *   off 28 telephonenumbers (array placeholder, empty here)
         *   off 32 DataBuffer: IMSI then ICCID (UTF-16LE, padded to 4)
         *
         * frame_base stays 0, so the string offsets are relative to the
         * InformationBuffer start (umbim mbim_get_string convention).
         *
         * Previous bug: the offsets stored 48 + fixed_len (i.e. included the
         * MBIM header), so the host read the strings 48 bytes too far -> the
         * malformed IMSI/ICCID seen in Wireshark.
         */
        struct mbim_wire_builder b;
        struct mbim_basic_connect_subscriber_ready_status *s;
        const char *imsi = state->sim_ready ? state->identity.imsi : "";
        const char *iccid = state->sim_ready ? state->identity.iccid : "";
        uint32_t readystate = state->sim_ready ? 1u : 0u; /* INITIALIZED:NOT_INIT */
        struct mbim_string id_ref, icc_ref;
        uint32_t info_len, total_msg_len;

        LOG_DBG(MBIM, "SUBSCRIBER_READY_STATUS query");

        mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
        s = (struct mbim_basic_connect_subscriber_ready_status *)b.buf;

        mbim_wire_reserve(&b, sizeof(*s));            /* fixed 32B, off 0 */
        mbim_wire_append_string(&b, imsi, &id_ref);   /* IMSI  -> off 32  */
        mbim_wire_append_string(&b, iccid, &icc_ref); /* ICCID -> after   */

        if (id_ref.length && id_ref.offset != sizeof(*s))
            LOG_ERR(MBIM, "SRS subscriberid off=%u expected=%zu",
                    id_ref.offset, sizeof(*s));

        put_le32(&s->readystate, readystate);
        mbim_wire_put_string(&s->subscriberid, id_ref);
        mbim_wire_put_string(&s->simiccid, icc_ref);
        put_le32(&s->readyinfo, 0);
        put_le32(&s->telephonenumberscount, 0);
        put_le32(&s->telephonenumbers, 0);

        info_len = mbim_wire_len(&b);
        total_msg_len = 48 + info_len;
        put_le32(&resp[4], total_msg_len);
        put_le32(&resp[44], info_len);
        *resp_len = total_msg_len;

        mbim_wire_finalize(&b, "SUBSCRIBER_READY_STATUS");
        mbim_dump_subscriber_ready_model(readystate, imsi, iccid, 0, 0);
        mbim_dump_subscriber_ready_wire(s, info_len, total_msg_len);
        mbim_wire_hexdump("SUBSCRIBER_READY_STATUS", b.buf, info_len);
        return true;
    } else if (cid == MBIM_CID_PROVISIONED_CONTEXTS) {
        /*
         * MBIM_PROVISIONED_CONTEXTS_INFO, single context:
         *   off 0  provisionedcontextscount = 1
         *   off 4  reflist[0] = { offset=12, size=60+apn_padded }  (OL_PAIR)
         *   off 12 mbimprovisionedcontextelement (60B fixed) + APN
         *
         * The element is the 60-byte layout WITH the trailing providerid
         * (RouterOS expects it; the 52-byte variant left it 8 bytes short).
         * providerid stays {0,0} here. The accessstring offset INSIDE the
         * element is element-relative (=60 = sizeof element), matching
         * Wireshark mbim_dissect_context(). frame_base is set to the element
         * start while appending the APN so the builder produces that
         * element-relative offset, then reset to 0.
         */
        static const uint8_t context_type_uuid[16] = {
            0xb4, 0x3f, 0x75, 0x8c, 0xa5, 0x60, 0x4b, 0x46,
            0xb3, 0x5e, 0xc5, 0x86, 0x96, 0x41, 0xfb, 0x54
        };
        struct mbim_wire_builder b;
        struct mbim_basic_connect_provisioned_contexts *hdr;
        struct mbimprovisionedcontextelement *el;
        struct mbim_string *ref;
        const char *apn = state->apn[0] ? state->apn : "internet";
        struct mbim_string apn_ref;
        uint32_t reflist_off, elem_off, elem_size, info_len, total_msg_len;

        mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
        hdr = (struct mbim_basic_connect_provisioned_contexts *)b.buf;

        /*
         * Fixed header is count(4) + one OL_PAIR(8). The umbim struct is only
         * 8 bytes (count + the first word of the ref array), so reserve the
         * count and the real 8-byte ref entry explicitly.
         */
        mbim_wire_reserve(&b, 4);                        /* count       off 0  */
        reflist_off = mbim_wire_reserve(&b, 8);          /* OL_PAIR     off 4  */
        elem_off = mbim_wire_reserve(&b, sizeof(*el));   /* element     off 12 */

        if (reflist_off != 4 || elem_off != 12)
            LOG_ERR(MBIM, "PROVISIONED_CONTEXTS bad offsets reflist=%u elem=%u",
                    reflist_off, elem_off);

        el = (struct mbimprovisionedcontextelement *)&b.buf[elem_off];

        b.frame_base = elem_off;                         /* element-relative   */
        mbim_wire_append_string(&b, apn, &apn_ref);      /* APN after element   */
        b.frame_base = 0;

        elem_size = mbim_wire_len(&b) - elem_off;        /* 60 + apn_padded     */

        if (apn_ref.length && apn_ref.offset != sizeof(*el))
            LOG_ERR(MBIM, "PROVISIONED_CONTEXTS accessstring off=%u expected=%zu",
                    apn_ref.offset, sizeof(*el));

        /* element fixed fields (username/password/providerid = {0,0},
         * compression/authprotocol = 0; all zero-filled by reserve) */
        put_le32(&el->contextid, 1);
        memcpy(el->contexttype, context_type_uuid, 16);
        mbim_wire_put_string(&el->accessstring, apn_ref);

        /* header + ref list */
        put_le32(&hdr->provisionedcontextscount, 1);
        ref = (struct mbim_string *)&b.buf[reflist_off];
        mbim_wire_put_string(ref, (struct mbim_string){ elem_off, elem_size });

        info_len = mbim_wire_len(&b);
        total_msg_len = 48 + info_len;
        put_le32(&resp[4], total_msg_len);
        put_le32(&resp[44], info_len);
        *resp_len = total_msg_len;

        mbim_wire_finalize(&b, "PROVISIONED_CONTEXTS");
        mbim_dump_provisioned_model(1, 1, "internet", apn);
        mbim_dump_provisioned_wire(1, elem_off, elem_size, el, info_len, total_msg_len);
        mbim_wire_hexdump("PROVISIONED_CONTEXTS", b.buf, info_len);
        return true;
    } else if (cid == MBIM_CID_REGISTER_STATE) {
        /* struct mbim_basic_connect_register_state (48B fixed) over the
         * InformationBuffer; provider strings stay {0,0} (none advertised). */
        struct mbim_basic_connect_register_state *r =
            (struct mbim_basic_connect_register_state *)&resp[48];

        LOG_DBG(MBIM, "REGISTER_STATE query");

        if (cmd_type != 0) {
            if (actions && actions->request_register)
                actions->request_register(actions->user);
            /* SET response: full 48-byte struct, registrationflag = 2. */
            put_le32(&r->nwerror, 0);
            put_le32(&r->registerstate, 1);
            put_le32(&r->registermode, 1);
            put_le32(&r->availabledataclasses, 0);
            put_le32(&r->currentcellularclass, 1);
            put_le32(&r->registrationflag, 2);
            put_le32(&resp[4], 48 + (uint32_t)sizeof(*r));
            put_le32(&resp[44], (uint32_t)sizeof(*r));
            *resp_len = 48 + (uint32_t)sizeof(*r);
            return true;
        }

        /*
         * QUERY response keeps the historical 44-byte InformationBuffer: the
         * trailing registrationflag is intentionally left out (RouterOS
         * accepts it that way), only the scalars + empty provider refs.
         */
        put_le32(&r->nwerror, 0);
        put_le32(&r->registerstate, state->registered_home ? 3 : 1);
        put_le32(&r->registermode, 1);
        put_le32(&r->availabledataclasses, state->packet_attached ? 0x20 : 0);
        put_le32(&r->currentcellularclass, 1);
        put_le32(&resp[4], 92);
        put_le32(&resp[44], 44);
        *resp_len = 92;
        return true;
    } else if (cid == MBIM_CID_PACKET_SERVICE) {
        /* struct mbim_basic_connect_packet_service (28B fixed). uplinkspeed /
         * downlinkspeed are 64-bit; written as low/high halves. */
        struct mbim_basic_connect_packet_service *ps =
            (struct mbim_basic_connect_packet_service *)&resp[48];
        uint8_t *ul = (uint8_t *)&ps->uplinkspeed;
        uint8_t *dl = (uint8_t *)&ps->downlinkspeed;

        LOG_DBG(MBIM, "PACKET_SERVICE query");
        put_le32(&ps->nwerror, 0);
        put_le32(&ps->packetservicestate, state->packet_attached ? 2 : 0);
        put_le32(&ps->highestavailabledataclass, state->packet_attached ? 0x20 : 0);
        put_le32(&ul[0], state->packet_attached ? 50000000u : 0u);  /* uplink lo */
        put_le32(&ul[4], 0);                                        /* uplink hi */
        put_le32(&dl[0], state->packet_attached ? 100000000u : 0u); /* downlink lo */
        put_le32(&dl[4], 0);                                        /* downlink hi */
        put_le32(&resp[4], 48 + (uint32_t)sizeof(*ps));
        put_le32(&resp[44], (uint32_t)sizeof(*ps));
        *resp_len = 48 + (uint32_t)sizeof(*ps);
        return true;
    } else if (cid == MBIM_CID_SIGNAL_STATE) {
        put_le32(&resp[4], 48);
        put_le32(&resp[44], 0);
        *resp_len = 48;
        return true;
    } else if (cid == MBIM_CID_CONNECT) {
        /* struct mbim_basic_connect_connect (36B fixed). */
        struct mbim_basic_connect_connect *c =
            (struct mbim_basic_connect_connect *)&resp[48];
        static const uint8_t uuid_context_type_internet[16] = {
            0x7e,0x5e,0x2a,0x7e,0x4e,0x6f,0x72,0x72,
            0x73,0x6b,0x65,0x6e,0x7e,0x5e,0x2a,0x7e
        };
        uint32_t activationstate;

        if (cmd_type == 1) {
            /* cmd[52..55] is IB offset 4; gate on the real buffer length, not the
             * host-declared ib_len. */
            uint32_t activation_command =
                (ib_len >= 8 && cmd_len >= 56) ? get_le32(&cmd[52]) : 1;
            LOG_DBG(MBIM, "CONNECT set session_id=%u activation_command=%u",
                    state->connect_session_id, activation_command);
            if (activation_command == 0) {
                if (actions && actions->request_disconnect)
                    actions->request_disconnect(actions->user);
                state->connect_activated = false;
                state->connect_session_id = 0;
                activationstate = 3;         /* DEACTIVATED */
            } else {
                if (actions && actions->request_connect)
                    actions->request_connect(actions->user, state->apn);
                state->connect_activated = true;
                state->connect_session_id = 0;
                activationstate = 1;         /* ACTIVATED */
            }
        } else {
            LOG_DBG(MBIM, "CONNECT query");
            activationstate = state->connect_activated ? 1 : 3; /* ACTIVATED:DEACTIVATED */
        }

        put_le32(&c->sessionid, state->connect_session_id);
        put_le32(&c->activationstate, activationstate);
        put_le32(&c->voicecallstate, 0);
        put_le32(&c->iptype, 1);            /* IPV4 */
        memcpy(c->contexttype, uuid_context_type_internet, 16);
        put_le32(&c->nwerror, 0);
        put_le32(&resp[4], 48 + (uint32_t)sizeof(*c));
        put_le32(&resp[44], (uint32_t)sizeof(*c));
        *resp_len = 48 + (uint32_t)sizeof(*c);
        return true;
    } else if (cid == MBIM_CID_IP_CONFIGURATION) {
        /*
         * struct mbim_basic_connect_ip_configuration (60B fixed), then a
         * mbimipv4element (prefix+addr) at offset 60, a 4-byte ref-ipv4
         * gateway at 68 and a 4-byte ipv4 DNS at 72. info_len = 76.
         */
        struct mbim_basic_connect_ip_configuration *ic =
            (struct mbim_basic_connect_ip_configuration *)&resp[48];
        uint32_t addr_off = (uint32_t)sizeof(*ic);                 /* 60 */
        uint32_t gw_off   = addr_off + (uint32_t)sizeof(struct mbimipv4element); /* 68 */
        uint32_t dns_off  = gw_off + 4;                            /* 72 */
        uint32_t info_len = dns_off + 4;                           /* 76 */
        struct mbimipv4element *addr =
            (struct mbimipv4element *)&resp[48 + addr_off];

        put_le32(&ic->sessionid, state->connect_session_id);
        put_le32(&ic->ipv4configurationavailable, 0x0f); /* addr|gw|dns|mtu */
        put_le32(&ic->ipv6configurationavailable, 0);
        put_le32(&ic->ipv4addresscount, 1);
        put_le32(&ic->ipv4address, addr_off);
        put_le32(&ic->ipv6addresscount, 0);
        put_le32(&ic->ipv6address, 0);
        put_le32(&ic->ipv4gateway, gw_off);
        put_le32(&ic->ipv6gateway, 0);
        put_le32(&ic->ipv4dnsservercount, 1);
        put_le32(&ic->ipv4dnsserver, dns_off);
        put_le32(&ic->ipv6dnsservercount, 0);
        put_le32(&ic->ipv6dnsserver, 0);
        put_le32(&ic->ipv4mtu, state->ip.mtu);
        put_le32(&ic->ipv6mtu, 0);

        put_le32(&addr->onlinkprefixlength, 24);
        memcpy(addr->ipv4address, state->ip.ipv4_addr, 4);
        memcpy(&resp[48 + gw_off], state->ip.ipv4_gw, 4);
        memcpy(&resp[48 + dns_off], state->ip.ipv4_dns1, 4);

        put_le32(&resp[4], 48 + info_len);
        put_le32(&resp[44], info_len);
        *resp_len = 48 + info_len;
        return true;
    } else if (cid == MBIM_CID_RADIO_STATE) {
        /* struct mbim_basic_connect_radio_state (8B fixed). */
        struct mbim_basic_connect_radio_state *rs =
            (struct mbim_basic_connect_radio_state *)&resp[48];

        LOG_DBG(MBIM, "RADIO_STATE %s", cmd_type == 1 ? "SET" : "QUERY");
        if (cmd_type == 1 && ib_len >= 4 && cmd_len >= 52) {
            uint32_t requested = get_le32(&cmd[48]);
            LOG_DBG(MBIM, "RADIO_STATE set requested=%u", requested);
            if (actions && actions->set_radio)
                actions->set_radio(actions->user, requested ? true : false);
            /*
             * HardwareRadioState is always 1 (radio hardware present).
             * SoftwareRadioState reflects the requested value directly,
             * since set_radio() just applied it. Reading g_modem_state
             * here would be stale (updated only in state_bridge_poll).
             */
            put_le32(&rs->hwradiostate, 1);
            put_le32(&rs->swradiostate, requested ? 1 : 0);
        } else {
            put_le32(&rs->hwradiostate, state->radio_hw_on ? 1 : 0);
            put_le32(&rs->swradiostate, state->radio_sw_on ? 1 : 0);
        }

        put_le32(&resp[4], 48 + (uint32_t)sizeof(*rs));
        put_le32(&resp[44], (uint32_t)sizeof(*rs));
        *resp_len = 48 + (uint32_t)sizeof(*rs);
        return true;
    } else if (cid == MBIM_CID_DEVICE_SERVICES) {
        /*
         * MBIM_DEVICE_SERVICES_INFO: header (struct
         * mbim_basic_connect_device_services, 12B) + a ref-struct-array of
         * mbimdeviceserviceelement, one per announced service. Each element is
         * cids_off + cidcount*4 bytes (cids_off = offsetof(cids) = 28).
         */
        static const struct {
            const uint8_t *uuid;
            uint32_t cids[5];
            uint32_t cidcount;
        } services[] = {
            { UUID_EXT_QMUX, { 1 }, 1 },
            { UUID_BASIC_CONNECT_EXTENSIONS,
              { MBIM_EXT_CID_PROVISIONED_CONTEXT_V2,
                MBIM_EXT_CID_LTE_ATTACH_CONFIG,
                MBIM_EXT_CID_LTE_ATTACH_STATUS }, 3 },
            { UUID_SMS,
              { MBIM_CID_SMS_CONFIGURATION, MBIM_CID_SMS_READ, MBIM_CID_SMS_SEND,
                MBIM_CID_SMS_DELETE, MBIM_CID_SMS_MESSAGE_STORE_STATUS }, 5 },
        };
        const uint32_t nsvc = sizeof(services) / sizeof(services[0]);
        const uint32_t cids_off = (uint32_t)offsetof(struct mbimdeviceserviceelement, cids);
        struct mbim_wire_builder b;
        struct mbim_basic_connect_device_services *ds;
        uint32_t reflist_off, info_len, total_msg_len;

        LOG_DBG(MBIM, "DEVICE_SERVICES query");

        mbim_wire_init(&b, &resp[48], MBIM_INFOBUF_CAP);
        ds = (struct mbim_basic_connect_device_services *)b.buf;
        mbim_wire_reserve(&b, 8);                  /* deviceservicescount + maxdsssessions */
        reflist_off = mbim_wire_reserve(&b, 8 * nsvc);

        for (uint32_t i = 0; i < nsvc; i++) {
            uint32_t elem_size = cids_off + services[i].cidcount * 4;
            uint32_t elem_off = mbim_wire_reserve(&b, elem_size);
            struct mbimdeviceserviceelement *e =
                (struct mbimdeviceserviceelement *)&b.buf[elem_off];
            struct mbim_string *ref =
                (struct mbim_string *)&b.buf[reflist_off + i * 8];

            memcpy(e->deviceserviceid, services[i].uuid, 16);
            put_le32(&e->dsspayload, 0);
            put_le32(&e->maxdssinstances, 0);
            put_le32(&e->cidscount, services[i].cidcount);
            for (uint32_t j = 0; j < services[i].cidcount; j++)
                put_le32((uint8_t *)&e->cids + j * 4, services[i].cids[j]);

            mbim_wire_put_string(ref, (struct mbim_string){ elem_off, elem_size });
        }

        put_le32(&ds->deviceservicescount, nsvc);
        put_le32(&ds->maxdsssessions, 0);

        info_len = mbim_wire_len(&b);
        total_msg_len = 48 + info_len;
        put_le32(&resp[4], total_msg_len);
        put_le32(&resp[44], info_len);
        *resp_len = total_msg_len;
        mbim_wire_finalize(&b, "DEVICE_SERVICES");
        LOG_DBG(MBIM, "DEVICE_SERVICES announce QMUX[1] BCE[1,3,4] SMS[1,2,3,4,5]");
        return true;
    }

    put_le32(&resp[4], 48);
    put_le32(&resp[44], 0);
    *resp_len = 48;
    return true;
}
