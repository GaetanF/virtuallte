#include "acm_at.h"
#include <stdio.h>
#include <string.h>
#include "../core.h"
#include "../common/log.h"

__attribute__((unused)) static void log_at_hex(const char *label, const uint8_t *data, size_t len)
{
    char hex[256];
    size_t i, pos = 0;
    for (i = 0; i < len && pos + 3 < sizeof(hex); i++) {
        snprintf(hex + pos, sizeof(hex) - pos, "%02x", data[i]);
        pos += 2;
    }
    hex[pos] = '\0';
    LOG_DBG(ACM, "%s %zu bytes: %s", label, len, hex);
}

const char *at_response(const char *cmd)
{
    static char buf[256];

    LOG_DBG(ACM, "AT RX: [%s]", cmd);

    if (strstr(cmd, "ATI")) {
        snprintf(buf, sizeof(buf),
                 "\r\n%s\r\n%s\r\nRevision: %s\r\n\r\nOK\r\n",
                 g_modem_state.identity.manufacturer,
                 g_modem_state.identity.model,
                 g_modem_state.identity.firmware);
        return buf;
    }

    if (strstr(cmd, "CGMI")) {
        snprintf(buf, sizeof(buf),
                 "\r\n%s\r\n\r\nOK\r\n",
                 g_modem_state.identity.manufacturer);
        return buf;
    }

    if (strstr(cmd, "CGMM")) {
        snprintf(buf, sizeof(buf),
                 "\r\n%s\r\n\r\nOK\r\n",
                 g_modem_state.identity.model);
        return buf;
    }

    if (strstr(cmd, "CGMR")) {
        snprintf(buf, sizeof(buf),
                 "\r\n%s\r\n\r\nOK\r\n",
                 g_modem_state.identity.firmware);
        return buf;
    }
    
    if (strstr(cmd, "EGMR=0,5")) {
        snprintf(buf, sizeof(buf),
                 "\r\n+EGMR: \"%s\"\r\n\r\nOK\r\n",
                 g_modem_state.identity.imei);
        return buf;
    }

    if (strstr(cmd, "CGSN")) {
        snprintf(buf, sizeof(buf),
                 "\r\n%s\r\n\r\nOK\r\n",
                 g_modem_state.identity.imei);
        return buf;
    }

    if (strstr(cmd, "CFUN?"))
        return "\r\n+CFUN: 1\r\n\r\nOK\r\n";

    if (strstr(cmd, "CSQ"))
        return "\r\n+CSQ: 20,99\r\n\r\nOK\r\n";

    /* SIM */
    if (strstr(cmd, "CPIN?")) {
        return g_modem_state.sim_ready
            ? "\r\n+CPIN: READY\r\n\r\nOK\r\n"
            : "\r\n+CPIN: NOT INSERTED\r\n\r\nOK\r\n";
    }

    if (!strcmp(cmd, "CIMI")) {
        static char cimi_buf[64];

        snprintf(cimi_buf, sizeof(cimi_buf),
                "\r\n%s\r\n\r\nOK\r\n",
                g_modem_state.identity.imsi);

        return cimi_buf;
    }

    if (strstr(cmd, "QCCID")) {
        static char qccid_buf[128];

        snprintf(qccid_buf, sizeof(qccid_buf),
                "\r\n+QCCID: %s\r\n\r\nOK\r\n",
                g_modem_state.identity.iccid);

        return qccid_buf;
    }

    /* OPERATOR */

    if (strstr(cmd, "COPS?")) {
        static char cops_buf[128];

        snprintf(cops_buf, sizeof(cops_buf),
                "\r\n+COPS: 0,2,\"%s\",7\r\n\r\nOK\r\n",
                g_modem_state.oper.plmn);

        return cops_buf;
    }

    /* REGISTRATION */

    if (strstr(cmd, "CREG?")) {
        static char creg_buf[64];

        snprintf(creg_buf, sizeof(creg_buf),
                "\r\n+CREG: 2,%d\r\n\r\nOK\r\n",
                g_modem_state.registered_home ? 1 : 0);

        return creg_buf;
    }

    if (strstr(cmd, "CGREG?")) {
        static char cgreg_buf[64];

        snprintf(cgreg_buf, sizeof(cgreg_buf),
                "\r\n+CGREG: 2,%d\r\n\r\nOK\r\n",
                g_modem_state.packet_attached ? 1 : 0);

        return cgreg_buf;
    }

    if (strstr(cmd, "CEREG?")) {
        static char cereg_buf[64];

        snprintf(cereg_buf, sizeof(cereg_buf),
                "\r\n+CEREG: 2,%d\r\n\r\nOK\r\n",
                g_modem_state.packet_attached ? 1 : 0);

        return cereg_buf;
    }

    /* CELL INFO */

    if (strstr(cmd, "QENG=\"servingcell\"")) {
        return g_modem_state.serving_connected
            ? "\r\n+QENG: \"servingcell\",\"CONNECT\",\"LTE\",\"FDD\",208,01,123456,100,6300,3,5,5,ABCD,-85,-10,-65,10,20,0,45\r\n\r\nOK\r\n"
            : "\r\n+QENG: \"servingcell\",\"NOCONN\"\r\n\r\nOK\r\n";
    }

    if (strstr(cmd, "QCAINFO?")) {
        return g_modem_state.serving_connected
            ? "\r\n+QCAINFO: \"PCC\",6300,100,\"LTE BAND 3\",1,100,-85,-10,-65,10\r\n\r\nOK\r\n"
            : "\r\nOK\r\n";
    }



    return "\r\nOK\r\n";
}
