#include <errno.h>
#include <linux/usb/raw_gadget.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "acm_worker.h"
#include "acm_at.h"
#include "../core.h"
#include "../common/log.h"

struct bulk_io
{
    struct usb_raw_ep_io io;
    char data[4096];
};

static void log_at_data(const char *label, const char *data, int len)
{
    char safe[512];
    int i, pos = 0;
    /* Bound on pos: an escaped \r/\n writes 2 chars, so bounding on i would
     * overflow safe[] for input full of CR/LF. Keep 3 bytes of headroom. */
    for (i = 0; i < len && data[i] && pos < (int)(sizeof(safe) - 3); i++) {
        if (data[i] == '\r') {
            safe[pos++] = '\\'; safe[pos++] = 'r';
        } else if (data[i] == '\n') {
            safe[pos++] = '\\'; safe[pos++] = 'n';
        } else {
            safe[pos++] = data[i];
        }
    }
    safe[pos] = '\0';
    LOG_DBG(ACM, "%s %d bytes: [%s]", label, len, safe);
}

void *acm_worker(void *arg)
{
    int fd = *(int *)arg;

    while (1)
    {
        if (acm_ep_out < 0 || acm_ep_in < 0)
        {
            usleep(100000);
            continue;
        }

        struct bulk_io rx;
        memset(&rx, 0, sizeof(rx));
        rx.io.ep = acm_ep_out;
        rx.io.flags = 0;
        rx.io.length = sizeof(rx.data) - 1;

        int rv = ioctl(fd, USB_RAW_IOCTL_EP_READ, &rx.io);
        if (rv < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            LOG_ERR(ACM, "USB_RAW_IOCTL_EP_READ ACM errno=%d", errno);
            usleep(100000);
            continue;
        }

        if (rv == 0)
            continue;

        rx.data[rv] = 0;

        log_at_data("ACM RX", rx.data, rv);

        const char *resp = at_response(rx.data);

        struct bulk_io tx;
        memset(&tx, 0, sizeof(tx));
        tx.io.ep = acm_ep_in;
        tx.io.flags = 0;
        tx.io.length = strlen(resp);

        memcpy(tx.data, resp, tx.io.length);

        LOG_TRC(ACM, "ACM TX ep=%d len=%u", acm_ep_in, (unsigned)tx.io.length);

        int wr = ioctl(fd, USB_RAW_IOCTL_EP_WRITE, &tx.io);
        if (wr < 0)
        {
            LOG_ERR(ACM, "USB_RAW_IOCTL_EP_WRITE ACM errno=%d", errno);
            usleep(100000);
            continue;
        }

        LOG_DBG(ACM, "ACM TX OK %d bytes", wr);
    }

    return NULL;
}
