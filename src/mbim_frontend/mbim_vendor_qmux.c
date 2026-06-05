#include "mbim_vendor_qmux.h"

#include <stdio.h>
#include <string.h>

#include "../common/log.h"
#include "../common/utils.h"
#include "mbim_protocol.h"

void mbim_vendor_qmux_reset(struct mbim_vendor_qmux_state *st)
{
    st->sync_ind_sent = false;
    st->sync_ind_pending = false;
    st->sync_ind_len = 0;
}

bool mbim_vendor_qmux_handle_ctl_sync(struct mbim_vendor_qmux_state *st,
                                      uint32_t mbim_tid,
                                      uint32_t cid,
                                      const uint8_t *service_id,
                                      const uint8_t *q,
                                      uint32_t q_len,
                                      mbim_vendor_enqueue_fn enqueue,
                                      void *user)
{
    uint8_t resp_qmi[19] = {
        0x01, 0x11, 0x00, 0x80, 0x00, 0x00, 0x00,
        0x00, 0x27, 0x00, 0x07, 0x00,
        0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    size_t resp_qmi_len = sizeof(resp_qmi);

    if (!q || q_len < 12)
        return false;

    LOG_DBG(QMI, "QMI_CTL_SYNC fields q_len=%u txn=%02x msgid=0x%04x",
           q_len, q[7], ((uint16_t)q[8]) | (((uint16_t)q[9]) << 8));

    {
        uint32_t i;
        uint32_t dump = q_len < 64 ? q_len : 64;
        char hex[512] = "";
        int hpos = 0;
        for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
            hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                             "%s%02x", i ? " " : "", q[i]);
        LOG_DBG(QMI, "QMI_CTL_SYNC req hex=%s%s", hex, q_len > dump ? " ..." : "");
    }

    resp_qmi[7] = q[7];
    resp_qmi[8] = q[8];
    resp_qmi[9] = q[9];
    LOG_DBG(QMI, "QMI_CTL_SYNC extracted txn=%u", (unsigned)q[7]);

    {
        uint8_t cmd_done_mbim[128];
        uint32_t cmd_done_len = 48 + (uint32_t)resp_qmi_len;

        memset(cmd_done_mbim, 0, sizeof(cmd_done_mbim));
        put_le32(&cmd_done_mbim[0], MBIM_COMMAND_DONE);
        put_le32(&cmd_done_mbim[4], cmd_done_len);
        put_le32(&cmd_done_mbim[8], mbim_tid);
        put_le32(&cmd_done_mbim[12], 1);
        put_le32(&cmd_done_mbim[16], 0);
        memcpy(&cmd_done_mbim[20], service_id, 16);
        put_le32(&cmd_done_mbim[36], cid);
        put_le32(&cmd_done_mbim[40], MBIM_STATUS_SUCCESS);
        put_le32(&cmd_done_mbim[44], resp_qmi_len);
        memcpy(&cmd_done_mbim[48], resp_qmi, resp_qmi_len);

        {
            size_t i;
            size_t dump = resp_qmi_len < 64 ? resp_qmi_len : 64;
            char hex[512] = "";
            int hpos = 0;
            for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
                hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                                 "%s%02x", i ? " " : "", resp_qmi[i]);
            LOG_DBG(QMI, "QMI_CTL_SYNC rsp qmi hex=%s%s",
                    hex, resp_qmi_len > dump ? " ..." : "");
        }

        {
            size_t i;
            size_t dump = cmd_done_len < 96 ? cmd_done_len : 96;
            char hex[768] = "";
            int hpos = 0;
            for (i = 0; i < dump && hpos < (int)sizeof(hex) - 4; i++)
                hpos += snprintf(hex + hpos, sizeof(hex) - (size_t)hpos,
                                 "%s%02x", i ? " " : "", cmd_done_mbim[i]);
            LOG_DBG(QMI, "QMI_CTL_SYNC rsp MBIM len=%u hex=%s%s",
                    cmd_done_len, hex, cmd_done_len > dump ? " ..." : "");
        }

        if (!enqueue(user, cmd_done_mbim, cmd_done_len))
            return false;
        LOG_TRC(QMI, "QMI_CTL_SYNC response sent txn=%u msg_id=0x%04x",
                (unsigned)q[7],
                (unsigned)((uint16_t)q[8] | ((uint16_t)q[9] << 8)));
    }

    if (!st->sync_ind_sent) {
        uint8_t ind_qmi[12] = {
            0x01, 0x0b, 0x00, 0x80, 0x00, 0x00,
            0x02, 0x00, 0x27, 0x00, 0x00, 0x00,
        };
        uint8_t ind_mbim[64];
        uint32_t ind_len = 44 + sizeof(ind_qmi);

        memset(ind_mbim, 0, sizeof(ind_mbim));
        put_le32(&ind_mbim[0], MBIM_INDICATE_STATUS_MSG);
        put_le32(&ind_mbim[4], ind_len);
        put_le32(&ind_mbim[8], 0);
        put_le32(&ind_mbim[12], 1);
        put_le32(&ind_mbim[16], 0);
        memcpy(&ind_mbim[20], UUID_EXT_QMUX, 16);
        put_le32(&ind_mbim[36], cid);
        put_le32(&ind_mbim[40], sizeof(ind_qmi));
        memcpy(&ind_mbim[44], ind_qmi, sizeof(ind_qmi));

        if (ind_len <= sizeof(st->sync_ind_buf)) {
            memcpy(st->sync_ind_buf, ind_mbim, ind_len);
            st->sync_ind_len = ind_len;
            st->sync_ind_pending = true;
            LOG_TRC(QMI, "QMI_CTL_SYNC indication deferred len=%zu", sizeof(ind_qmi));
        } else {
            st->sync_ind_pending = false;
            st->sync_ind_len = 0;
            LOG_ERR(QMI, "QMI_CTL_SYNC indication dropped len=%u (buffer too small)", ind_len);
        }
    } else {
        LOG_DBG(QMI, "INDICATE_STATUS already sent, skip enqueue");
    }

    return true;
}

bool mbim_vendor_qmux_has_pending_indication(const struct mbim_vendor_qmux_state *st)
{
    return st->sync_ind_pending;
}

uint32_t mbim_vendor_qmux_take_pending_indication(struct mbim_vendor_qmux_state *st,
                                                  uint8_t *out,
                                                  uint32_t out_size)
{
    if (!st->sync_ind_pending || st->sync_ind_len == 0 || st->sync_ind_len > out_size)
        return 0;

    memcpy(out, st->sync_ind_buf, st->sync_ind_len);
    st->sync_ind_pending = false;
    return st->sync_ind_len;
}

void mbim_vendor_qmux_mark_indication_sent(struct mbim_vendor_qmux_state *st)
{
    st->sync_ind_sent = true;
    st->sync_ind_len = 0;
}
