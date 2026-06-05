#include "ue_backend.h"

#include <string.h>
#include <time.h>
#include <stdint.h>

#include "../modem_state/modem_state.h"

enum fake_reg_phase {
    FAKE_REG_IDLE = 0,
    FAKE_REG_SEARCHING,
    FAKE_REG_HOME,
};

enum fake_pkt_phase {
    FAKE_PKT_IDLE = 0,
    FAKE_PKT_ATTACHING,
    FAKE_PKT_ATTACHED,
};

enum fake_conn_phase {
    FAKE_CONN_IDLE = 0,
    FAKE_CONN_ACTIVATING,
    FAKE_CONN_ACTIVATED,
};

struct fake_backend_state {
    struct modem_state state;
    enum fake_reg_phase reg_phase;
    enum fake_pkt_phase pkt_phase;
    enum fake_conn_phase conn_phase;
    bool running;
    uint64_t reg_deadline_ms;
    uint64_t pkt_deadline_ms;
    uint64_t conn_deadline_ms;
};

static struct fake_backend_state g_fake;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int fake_init(void)
{
    modem_state_init_defaults(&g_fake.state);
    g_fake.reg_phase = FAKE_REG_IDLE;
    g_fake.pkt_phase = FAKE_PKT_IDLE;
    g_fake.conn_phase = FAKE_CONN_IDLE;
    g_fake.running = false;
    g_fake.reg_deadline_ms = 0;
    g_fake.pkt_deadline_ms = 0;
    g_fake.conn_deadline_ms = 0;

    g_fake.state.connect_activated = false;

    return 0;
}

static int fake_start(void)
{
    g_fake.running = true;
    return 0;
}

static int fake_stop(void)
{
    g_fake.running = false;
    return 0;
}

static int fake_set_radio(bool on)
{
    g_fake.state.radio_sw_on = on;

    if (!on) {
        g_fake.state.registered_home = false;
        g_fake.state.packet_attached = false;
        g_fake.state.serving_connected = false;
        g_fake.state.connect_activated = false;
        g_fake.reg_phase = FAKE_REG_IDLE;
        g_fake.pkt_phase = FAKE_PKT_IDLE;
        g_fake.conn_phase = FAKE_CONN_IDLE;
    }

    return 0;
}

static int fake_request_register(void)
{
    uint64_t t = now_ms();

    if (!g_fake.state.radio_sw_on)
        return 0;

    g_fake.state.registered_home = false;
    g_fake.state.packet_attached = false;
    g_fake.state.serving_connected = false;

    g_fake.reg_phase = FAKE_REG_SEARCHING;
    g_fake.reg_deadline_ms = t + 120;

    g_fake.pkt_phase = FAKE_PKT_IDLE;
    g_fake.conn_phase = FAKE_CONN_IDLE;

    return 0;
}

static int fake_request_connect(const char *apn)
{
    uint64_t t = now_ms();

    if (apn && apn[0] != '\0') {
        strncpy(g_fake.state.apn, apn, sizeof(g_fake.state.apn) - 1);
        g_fake.state.apn[sizeof(g_fake.state.apn) - 1] = '\0';
    }

    if (g_fake.state.packet_attached) {
        g_fake.conn_phase = FAKE_CONN_ACTIVATING;
        g_fake.conn_deadline_ms = t + 80;
    } else {
        g_fake.conn_phase = FAKE_CONN_IDLE;
    }

    return 0;
}

static int fake_request_disconnect(void)
{
    g_fake.conn_phase = FAKE_CONN_IDLE;
    g_fake.state.connect_activated = false;
    return 0;
}

static int fake_poll(struct modem_state *state)
{
    uint64_t t = now_ms();

    if (!g_fake.running) {
        *state = g_fake.state;
        return 0;
    }

    if (g_fake.reg_phase == FAKE_REG_SEARCHING && t >= g_fake.reg_deadline_ms) {
        g_fake.state.registered_home = true;
        g_fake.state.serving_connected = true;
        g_fake.reg_phase = FAKE_REG_HOME;
        g_fake.pkt_phase = FAKE_PKT_ATTACHING;
        g_fake.pkt_deadline_ms = t + 120;
    }

    if (g_fake.pkt_phase == FAKE_PKT_ATTACHING && t >= g_fake.pkt_deadline_ms) {
        g_fake.state.packet_attached = true;
        g_fake.pkt_phase = FAKE_PKT_ATTACHED;
        if (g_fake.conn_phase == FAKE_CONN_IDLE) {
            g_fake.conn_phase = FAKE_CONN_ACTIVATING;
            g_fake.conn_deadline_ms = t + 80;
        }
    }

    if (g_fake.conn_phase == FAKE_CONN_ACTIVATING && t >= g_fake.conn_deadline_ms) {
        g_fake.state.connect_activated = true;
        g_fake.state.connect_session_id = 0;
        g_fake.conn_phase = FAKE_CONN_ACTIVATED;
    }

    *state = g_fake.state;
    return 0;
}

const struct ue_backend *ue_backend_fake_get(void)
{
    static const struct ue_backend ops = {
        .init = fake_init,
        .start = fake_start,
        .stop = fake_stop,
        .set_radio = fake_set_radio,
        .request_register = fake_request_register,
        .request_connect = fake_request_connect,
        .request_disconnect = fake_request_disconnect,
        .poll = fake_poll,
    };

    return &ops;
}
