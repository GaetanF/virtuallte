#include "modem_state.h"

#include <string.h>

struct modem_state g_modem_state;

void modem_state_init_defaults(struct modem_state *st)
{
    memset(st, 0, sizeof(*st));

    st->sim_ready = true;
    st->radio_hw_on = true;
    st->radio_sw_on = true;
    st->registered_home = true;
    st->packet_attached = true;
    st->serving_connected = true;
    st->connect_activated = false;
    st->connect_session_id = 0;

    strcpy(st->apn, "internet");

    strcpy(st->identity.imei, "867530900000001");
    strcpy(st->identity.imsi, "208010123456789");
    strcpy(st->identity.iccid, "8933012345678901234");
    strcpy(st->identity.manufacturer, "Quectel");
    strcpy(st->identity.model, "RM520N-GL");
    strcpy(st->identity.firmware, "FAKA01");
    strcpy(st->identity.serial, "FAKE-0001");

    strcpy(st->oper.plmn, "20801");
    strcpy(st->oper.name, "EllaLab");

    st->ip.ipv4_addr[0] = 1;
    st->ip.ipv4_addr[1] = 2;
    st->ip.ipv4_addr[2] = 3;
    st->ip.ipv4_addr[3] = 4;

    st->ip.ipv4_gw[0] = 5;
    st->ip.ipv4_gw[1] = 6;
    st->ip.ipv4_gw[2] = 7;
    st->ip.ipv4_gw[3] = 8;

    st->ip.ipv4_dns1[0] = 9;
    st->ip.ipv4_dns1[1] = 10;
    st->ip.ipv4_dns1[2] = 11;
    st->ip.ipv4_dns1[3] = 12;

    st->ip.mtu = 1500;
}
