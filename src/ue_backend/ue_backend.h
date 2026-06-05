#ifndef UE_BACKEND_H
#define UE_BACKEND_H

#include <stdbool.h>

struct modem_state;

struct ue_backend {
    int (*init)(void);
    int (*start)(void);
    int (*stop)(void);
    int (*set_radio)(bool on);
    int (*request_register)(void);
    int (*request_connect)(const char *apn);
    int (*request_disconnect)(void);
    int (*poll)(struct modem_state *state);
};

const struct ue_backend *ue_backend_fake_get(void);

#endif
