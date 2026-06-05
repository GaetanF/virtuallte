#ifndef MODEM_STATE_H
#define MODEM_STATE_H

#include <stdbool.h>
#include <stdint.h>

struct modem_identity {
    char imei[32];
    char imsi[32];
    char iccid[40];
    char manufacturer[64];
    char model[64];
    char firmware[64];
    char serial[64];
};

struct modem_operator {
    char plmn[16];
    char name[64];
};

struct modem_ip_config {
    uint8_t ipv4_addr[4];
    uint8_t ipv4_gw[4];
    uint8_t ipv4_dns1[4];
    uint32_t mtu;
};

struct modem_state {
    bool sim_ready;
    bool radio_hw_on;
    bool radio_sw_on;
    bool registered_home;
    bool packet_attached;
    bool serving_connected;
    bool connect_activated;
    uint32_t connect_session_id;
    char apn[64];
    struct modem_identity identity;
    struct modem_operator oper;
    struct modem_ip_config ip;
};

extern struct modem_state g_modem_state;

void modem_state_init_defaults(struct modem_state *st);

#endif
