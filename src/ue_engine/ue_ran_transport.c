/*
 * ue_ran_transport.c - Real RAN transport via RLS/UDP toward gNB.
 *
 * UERANSIM anchor:
 *   - src/ue/rls/udp_task.cpp   : UDP loop, heartbeat, cell tracking
 *   - src/ue/rls/ctl_task.cpp   : PDU ack, downlink dispatch
 *   - src/lib/rls/rls_pdu.cpp   : wire format
 *
 * This is real network code: socket(), sendto(), recvfrom().
 */

#include "ue_ran_transport.h"
#include "ue_rls.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../common/log.h"

static void *ran_hb_worker(void *arg);
static void *ran_rx_worker(void *arg);

static uint64_t ran_now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

enum {
    UE_RAN_DEFAULT_RLS_PORT    = 4997,
    UE_RAN_DEFAULT_HB_INTERVAL = 1000,
    UE_RAN_DEFAULT_HB_TIMEOUT  = 2000,
    UE_RAN_ACK_SEND_INTERVAL   = 2250,
};

/* ---- Queue helpers ---- */

static bool rx_queue_full(int head, int tail)
{
    return ((tail + 1) % UE_RAN_RX_QUEUE_SIZE) == head;
}

static bool rx_queue_empty(int head, int tail)
{
    return head == tail;
}

static struct ue_ran_rx_entry *rx_queue_push(struct ue_ran_rx_entry *q,
                                             int *tail)
{
    struct ue_ran_rx_entry *e = &q[*tail];
    *tail = (*tail + 1) % UE_RAN_RX_QUEUE_SIZE;
    memset(e, 0, sizeof(*e));
    e->valid = true;
    return e;
}

static struct ue_ran_rx_entry *rx_queue_peek(struct ue_ran_rx_entry *q,
                                             int head, int tail)
{
    if (rx_queue_empty(head, tail))
        return NULL;
    return &q[head];
}

static void rx_queue_pop(int *head)
{
    *head = (*head + 1) % UE_RAN_RX_QUEUE_SIZE;
}

/* ---- Resolve gNB address to sockaddr ---- */

static int resolve_endpoint(const char *address, uint16_t port,
                            struct sockaddr_storage *out, socklen_t *out_len)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)out;

    memset(out, 0, sizeof(*out));
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);

    if (inet_pton(AF_INET, address, &sin->sin_addr) == 1) {
        *out_len = sizeof(struct sockaddr_in);
        return 0;
    }

    /* Try hostname resolution */
    {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;

        if (getaddrinfo(address, NULL, &hints, &res) != 0)
            return -1;

        memcpy(out, res->ai_addr, res->ai_addrlen);
        sin->sin_port = htons(port);
        *out_len = (socklen_t)res->ai_addrlen;
        freeaddrinfo(res);
        return 0;
    }
}

/* ---- Init / Config ---- */

void ue_ran_transport_init(struct ue_ran_transport_ctx *t)
{
    if (!t)
        return;
    memset(t, 0, sizeof(*t));
    t->state = UE_RAN_TRANSPORT_IDLE;
    t->socket_fd = -1;
    t->serving_cell_id = -1;
    t->next_cell_id = 1;
    t->heartbeat_interval_ms = UE_RAN_DEFAULT_HB_INTERVAL;
    t->heartbeat_timeout_ms = UE_RAN_DEFAULT_HB_TIMEOUT;
    t->next_pdu_id = 1;

    /* Random STI */
    t->sti = ((uint64_t)(uint32_t)rand() << 32) | (uint64_t)(uint32_t)rand();

    pthread_mutex_init(&t->hb_lock, NULL);
    t->hb_thread_started = false;
    t->hb_run = false;

    pthread_mutex_init(&t->rx_lock, NULL);
    t->rx_thread_started = false;
    t->rx_run = false;
    t->on_data_rx = NULL;
    t->on_data_rx_ctx = NULL;
}

void ue_ran_transport_set_data_rx_cb(struct ue_ran_transport_ctx *t,
                                     void (*cb)(void *), void *ctx)
{
    if (!t)
        return;
    t->on_data_rx = cb;
    t->on_data_rx_ctx = ctx;
}

/*
 * Dedicated heartbeat thread: sends an RLS heartbeat to every configured gNB
 * every heartbeat_interval, independently of the engine tick, using its OWN
 * buffer (never t->tx_buf). Only touches socket_fd/state under hb_lock; sti and
 * gnb_list are immutable after configure(). This keeps the gNB from declaring
 * the UE "signal lost" if the main thread stalls.
 */
static void *ran_hb_worker(void *arg)
{
    struct ue_ran_transport_ctx *t = arg;
    uint8_t buf[64];

    while (t->hb_run) {
        pthread_mutex_lock(&t->hb_lock);
        if (t->socket_fd >= 0 && t->state != UE_RAN_TRANSPORT_IDLE) {
            int i;
            for (i = 0; i < t->gnb_count; i++) {
                struct sockaddr_storage ss;
                socklen_t ss_len;
                int enc;

                if (resolve_endpoint(t->gnb_list[i].address,
                                     t->gnb_list[i].port, &ss, &ss_len) < 0)
                    continue;
                enc = ue_rls_encode_heartbeat(buf, sizeof(buf), t->sti, 0, 0, 0);
                if (enc > 0)
                    sendto(t->socket_fd, buf, (size_t)enc, 0,
                           (struct sockaddr *)&ss, ss_len);
            }
        }
        pthread_mutex_unlock(&t->hb_lock);
        usleep(t->heartbeat_interval_ms * 1000u);
    }
    return NULL;
}

int ue_ran_transport_configure(struct ue_ran_transport_ctx *t,
                               const char *gnb_addresses[],
                               int count,
                               uint16_t default_port)
{
    int i;

    if (!t || !gnb_addresses || count <= 0)
        return -1;
    if (count > UE_RAN_TRANSPORT_MAX_GNB)
        count = UE_RAN_TRANSPORT_MAX_GNB;

    for (i = 0; i < count; i++) {
        if (ue_ran_transport_add_gnb(t, gnb_addresses[i],
                                     default_port ? default_port : UE_RAN_DEFAULT_RLS_PORT) < 0)
            return -1;
    }
    return 0;
}

int ue_ran_transport_add_gnb(struct ue_ran_transport_ctx *t,
                             const char *address,
                             uint16_t port)
{
    struct ue_ran_gnb_endpoint *ep;

    if (!t || !address)
        return -1;
    if (t->gnb_count >= UE_RAN_TRANSPORT_MAX_GNB)
        return -1;

    ep = &t->gnb_list[t->gnb_count];
    strncpy(ep->address, address, sizeof(ep->address) - 1);
    ep->address[sizeof(ep->address) - 1] = '\0';
    ep->port = port ? port : UE_RAN_DEFAULT_RLS_PORT;
    t->gnb_count++;
    return 0;
}

/* ---- Start / Stop ---- */

int ue_ran_transport_start(struct ue_ran_transport_ctx *t)
{
    int fd;
    int flags;

    if (!t)
        return -1;
    if (t->gnb_count == 0)
        return -1;

    /* Open UDP socket */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_ERR(RAN, "socket() failed errno=%d", errno);
        return -1;
    }

    /* Set non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        LOG_ERR(RAN, "fcntl F_GETFL failed errno=%d", errno);
        close(fd);
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOG_ERR(RAN, "fcntl F_SETFL failed errno=%d", errno);
        close(fd);
        return -1;
    }

    /*
     * Reset per-session state BEFORE advertising the socket + SEARCHING state to
     * the long-lived rx thread. While state is still IDLE / socket_fd<0 the rx
     * thread idles, so these resets cannot race it or wipe a freshly-received
     * PDU. The socket_fd + state assignment is done last, under hb_lock.
     */
    t->last_heartbeat_ms = 0;
    t->last_ack_send_ms = 0;
    t->pending_ack_count = 0;
    t->data_queue_head = t->data_queue_tail = 0;

    pthread_mutex_lock(&t->rx_lock);
    t->nas_queue_head = t->nas_queue_tail = 0;
    pthread_mutex_unlock(&t->rx_lock);

    pthread_mutex_lock(&t->hb_lock);
    memset(t->cells, 0, sizeof(t->cells));
    t->cell_count = 0;
    t->serving_cell_id = -1;
    t->socket_fd = fd;
    t->state = UE_RAN_TRANSPORT_SEARCHING;
    pthread_mutex_unlock(&t->hb_lock);

    LOG_INF(RAN, "transport started, searching for cells");

    /* Long-lived heartbeat thread (started once; it idles when socket_fd<0). */
    if (!t->hb_thread_started) {
        t->hb_run = true;
        if (pthread_create(&t->hb_thread, NULL, ran_hb_worker, t) == 0) {
            t->hb_thread_started = true;
            LOG_INF(RAN, "RLS heartbeat thread started");
        } else {
            LOG_ERR(RAN, "failed to start RLS heartbeat thread");
        }
    }

    /*
     * Long-lived receive thread (started once; it idles when socket_fd<0).
     * Sole reader of the socket: decodes RLS datagrams off the EP0/engine
     * thread so downlink latency no longer tracks the EP0 tick cadence.
     */
    if (!t->rx_thread_started) {
        t->rx_run = true;
        if (pthread_create(&t->rx_thread, NULL, ran_rx_worker, t) == 0) {
            t->rx_thread_started = true;
            LOG_INF(RAN, "RLS receive thread started");
        } else {
            LOG_ERR(RAN, "failed to start RLS receive thread");
        }
    }

    return 0;
}

void ue_ran_transport_stop(struct ue_ran_transport_ctx *t)
{
    if (!t)
        return;

    /*
     * Set IDLE + close the socket and clear the cell table under hb_lock: once
     * state==IDLE / socket_fd<0 the long-lived rx thread idles and stops
     * touching the shared state. nas_queue is cleared under rx_lock since the
     * engine thread also dequeues it. Without this ordering, re-enabling the
     * radio raced the rx thread and corrupted nas_queue, so the post-restart
     * downlink NAS (auth/RRC) was never delivered and registration stalled.
     */
    pthread_mutex_lock(&t->hb_lock);
    if (t->socket_fd >= 0) {
        close(t->socket_fd);
        t->socket_fd = -1;
    }
    t->state = UE_RAN_TRANSPORT_IDLE;
    memset(t->cells, 0, sizeof(t->cells));
    t->cell_count = 0;
    t->serving_cell_id = -1;
    pthread_mutex_unlock(&t->hb_lock);

    pthread_mutex_lock(&t->rx_lock);
    t->nas_queue_head = t->nas_queue_tail = 0;
    pthread_mutex_unlock(&t->rx_lock);

    t->data_queue_head = t->data_queue_tail = 0;
    t->pending_ack_count = 0;

    LOG_INF(RAN, "transport stopped");
}

void ue_ran_transport_refresh_sti(struct ue_ran_transport_ctx *t)
{
    if (!t)
        return;
    t->sti = ((uint64_t)(uint32_t)rand() << 32) | (uint64_t)(uint32_t)rand();
    LOG_DBG(RAN, "RLS STI refreshed");
}

void ue_ran_transport_deinit(struct ue_ran_transport_ctx *t)
{
    if (!t)
        return;

    /* Closes the socket and sets state IDLE; the long-lived threads then idle. */
    ue_ran_transport_stop(t);

    /*
     * Stop and join the RX/HB threads BEFORE wiping the context — otherwise they
     * keep touching t (mutexes, queues) after the memset (use-after-free). The
     * RX thread exits within one poll timeout (~50 ms), the HB thread within one
     * heartbeat interval (~1 s).
     */
    if (t->rx_thread_started) {
        t->rx_run = false;
        pthread_join(t->rx_thread, NULL);
        t->rx_thread_started = false;
    }
    if (t->hb_thread_started) {
        t->hb_run = false;
        pthread_join(t->hb_thread, NULL);
        t->hb_thread_started = false;
    }

    pthread_mutex_destroy(&t->rx_lock);
    pthread_mutex_destroy(&t->hb_lock);

    memset(t, 0, sizeof(*t));
    t->socket_fd = -1;
    t->serving_cell_id = -1;
}

/* ---- Cell management ---- */

static struct ue_ran_cell_info *find_cell_by_sti(struct ue_ran_transport_ctx *t,
                                                  uint64_t sti)
{
    int i;
    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (t->cells[i].valid && t->cells[i].sti == sti)
            return &t->cells[i];
    }
    return NULL;
}

static struct ue_ran_cell_info *find_cell_by_id(struct ue_ran_transport_ctx *t,
                                                 int cell_id)
{
    int i;
    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (t->cells[i].valid && t->cells[i].cell_id == cell_id)
            return &t->cells[i];
    }
    return NULL;
}

static struct ue_ran_cell_info *alloc_cell(struct ue_ran_transport_ctx *t)
{
    int i;
    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (!t->cells[i].valid) {
            memset(&t->cells[i], 0, sizeof(t->cells[i]));
            t->cells[i].valid = true;
            t->cells[i].cell_id = t->next_cell_id++;
            t->cell_count++;
            return &t->cells[i];
        }
    }
    return NULL;
}

static void select_best_serving_cell(struct ue_ran_transport_ctx *t)
{
    int i, best_dbm = -999, best_id = -1;

    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (t->cells[i].valid && t->cells[i].dbm > best_dbm) {
            best_dbm = t->cells[i].dbm;
            best_id = t->cells[i].cell_id;
        }
    }
    t->serving_cell_id = best_id;
}

/*
 * Cell-table writers (expire_cells, handle_heartbeat_ack) run on the rx thread
 * and take hb_lock so the sender threads see a consistent table. The lock-free
 * helpers above (find_cell_by_*, alloc_cell, select_best_serving_cell) must only
 * be called with hb_lock already held.
 */
static void expire_cells(struct ue_ran_transport_ctx *t, uint64_t now_ms)
{
    int i;
    bool serving_lost = false;

    pthread_mutex_lock(&t->hb_lock);
    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (!t->cells[i].valid)
            continue;
        if (now_ms - t->cells[i].last_seen_ms > t->heartbeat_timeout_ms) {
            if (t->cells[i].cell_id == t->serving_cell_id)
                serving_lost = true;
            t->cells[i].valid = false;
            t->cell_count--;
        }
    }

    if (serving_lost) {
        select_best_serving_cell(t);
        if (t->serving_cell_id < 0)
            t->state = UE_RAN_TRANSPORT_LOST;
    }
    pthread_mutex_unlock(&t->hb_lock);
}

/* ---- sendto wrapper ---- */

static int send_to_cell(struct ue_ran_transport_ctx *t,
                        struct ue_ran_cell_info *cell,
                        const uint8_t *data, size_t len)
{
    ssize_t rc;

    if (t->socket_fd < 0 || !cell || cell->addr_len == 0)
        return -1;

    rc = sendto(t->socket_fd, data, len, 0,
                (struct sockaddr *)cell->addr_storage,
                cell->addr_len);
    if (rc < 0) {
        LOG_ERR(RAN, "sendto cell failed errno=%d", errno);
        return -1;
    }

    LOG_TRC(RAN, "sendto cell id=%d sent=%zd bytes", cell->cell_id, rc);
    t->tx_bytes += (uint64_t)rc;
    return 0;
}

static int send_to_addr(struct ue_ran_transport_ctx *t,
                        const struct sockaddr *addr, socklen_t addr_len,
                        const uint8_t *data, size_t len)
{
    ssize_t rc;

    if (t->socket_fd < 0)
        return -1;

    rc = sendto(t->socket_fd, data, len, 0, addr, addr_len);
    if (rc < 0) {
        LOG_ERR(RAN, "sendto addr failed errno=%d", errno);
        return -1;
    }

    t->tx_bytes += (uint64_t)rc;
    return 0;
}

/* ---- Heartbeat send ---- */

static void send_heartbeats(struct ue_ran_transport_ctx *t, uint64_t now_ms)
{
    int i, enc_len;
    struct sockaddr_storage ss;
    socklen_t ss_len;

    for (i = 0; i < t->gnb_count; i++) {
        if (resolve_endpoint(t->gnb_list[i].address,
                             t->gnb_list[i].port,
                             &ss, &ss_len) < 0)
            continue;

        enc_len = ue_rls_encode_heartbeat(t->tx_buf, sizeof(t->tx_buf),
                                          t->sti, 0, 0, 0);
        if (enc_len <= 0)
            continue;

        send_to_addr(t, (struct sockaddr *)&ss, ss_len,
                     t->tx_buf, (size_t)enc_len);
    }

    t->last_heartbeat_ms = now_ms;
}

/* ---- Pending ACK send ---- */

static void send_pending_acks(struct ue_ran_transport_ctx *t, uint64_t now_ms)
{
    struct ue_ran_cell_info *cell;
    int enc_len;

    if (t->pending_ack_count == 0)
        return;

    cell = find_cell_by_id(t, t->serving_cell_id);
    if (!cell)
        goto clear;

    enc_len = ue_rls_encode_pdu_ack(t->tx_buf, sizeof(t->tx_buf),
                                    t->sti,
                                    t->pending_ack_ids,
                                    (uint32_t)t->pending_ack_count);
    if (enc_len > 0)
        send_to_cell(t, cell, t->tx_buf, (size_t)enc_len);

clear:
    t->pending_ack_count = 0;
    t->last_ack_send_ms = now_ms;
}

/* ---- Process received RLS messages ---- */

static void handle_heartbeat_ack(struct ue_ran_transport_ctx *t,
                                 const struct ue_rls_heartbeat_ack *ack,
                                 const struct sockaddr *peer_addr,
                                 socklen_t peer_len,
                                 uint64_t now_ms)
{
    struct ue_ran_cell_info *cell;

    pthread_mutex_lock(&t->hb_lock);

    cell = find_cell_by_sti(t, ack->sti);
    if (!cell) {
        /* New cell discovered */
        cell = alloc_cell(t);
        if (!cell) {
            pthread_mutex_unlock(&t->hb_lock);
            return;
        }
        cell->sti = ack->sti;
    }

    cell->dbm = ack->dbm;
    cell->last_seen_ms = now_ms;
    memcpy(cell->addr_storage, peer_addr,
           peer_len < sizeof(cell->addr_storage) ? peer_len : sizeof(cell->addr_storage));
    cell->addr_len = peer_len;

    /* Reselect serving cell on signal change */
    select_best_serving_cell(t);

    pthread_mutex_unlock(&t->hb_lock);
}

static void handle_pdu_transmission(struct ue_ran_transport_ctx *t,
                                    const struct ue_rls_pdu_transmission *pdu)
{
    struct ue_ran_rx_entry *e;

    t->rx_pdu_count++;
    t->rx_bytes += pdu->pdu_len;

    LOG_TRC(RAN, "PDU recv type=%s pdu_id=%u pdu_len=%u",
            pdu->pdu_type == UE_RLS_PDU_TYPE_RRC ? "RRC" : "DATA",
            pdu->pdu_id, pdu->pdu_len);

    /* Track ACK */
    if (pdu->pdu_id != 0 && t->pending_ack_count < UE_RAN_PENDING_ACK_MAX)
        t->pending_ack_ids[t->pending_ack_count++] = pdu->pdu_id;

    if (pdu->pdu_type == UE_RLS_PDU_TYPE_RRC) {
        /* NAS/RRC PDU → NAS queue (consumed by the engine main thread). */
        pthread_mutex_lock(&t->rx_lock);
        if (rx_queue_full(t->nas_queue_head, t->nas_queue_tail)) {
            pthread_mutex_unlock(&t->rx_lock);
            LOG_WRN(RAN, "NAS queue full, dropping RRC PDU");
            return;
        }
        e = rx_queue_push(t->nas_queue, &t->nas_queue_tail);
        e->pdu_type = UE_RLS_PDU_TYPE_RRC;
        e->psi = 0;
        e->rrc_channel = pdu->payload;  /* DL_CCCH=2, DL_DCCH=3, etc. */
        e->len = (pdu->pdu_len <= UE_RAN_RX_PDU_MAX) ? pdu->pdu_len : UE_RAN_RX_PDU_MAX;
        if (pdu->pdu && e->len > 0)
            memcpy(e->data, pdu->pdu, e->len);
        LOG_TRC(RAN, "NAS queue: enqueued RRC PDU %u bytes ch=%u (queued=%d)",
                e->len, e->rrc_channel,
                (t->nas_queue_tail - t->nas_queue_head + UE_RAN_RX_QUEUE_SIZE) % UE_RAN_RX_QUEUE_SIZE);
        pthread_mutex_unlock(&t->rx_lock);
    } else if (pdu->pdu_type == UE_RLS_PDU_TYPE_DATA) {
        /* User plane DATA PDU → data queue */
        if (rx_queue_full(t->data_queue_head, t->data_queue_tail)) {
            LOG_WRN(RAN, "DATA queue full, dropping DATA PDU");
            return;
        }
        e = rx_queue_push(t->data_queue, &t->data_queue_tail);
        e->pdu_type = UE_RLS_PDU_TYPE_DATA;
        e->psi = (int)pdu->payload;
        e->len = (pdu->pdu_len <= UE_RAN_RX_PDU_MAX) ? pdu->pdu_len : UE_RAN_RX_PDU_MAX;
        if (pdu->pdu && e->len > 0)
            memcpy(e->data, pdu->pdu, e->len);
        LOG_TRC(RAN, "DATA queue: enqueued PDU psi=%d %u bytes", e->psi, e->len);
    }
}

/* IPv4 sockaddr equality on address + port (ignores sin_zero padding). */
static bool sa_in_equal(const struct sockaddr *a, const struct sockaddr *b)
{
    const struct sockaddr_in *x = (const struct sockaddr_in *)a;
    const struct sockaddr_in *y = (const struct sockaddr_in *)b;

    if (a->sa_family != AF_INET || b->sa_family != AF_INET)
        return false;
    return x->sin_addr.s_addr == y->sin_addr.s_addr &&
           x->sin_port == y->sin_port;
}

/*
 * Accept an inbound RLS datagram only from a known gNB: a learned cell (fast
 * path, covers DATA/RRC from the serving cell) or a configured gNB endpoint
 * (bootstrap heartbeat-ack, low rate so resolving here is fine). This rejects
 * injected/spoofed RLS traffic from arbitrary sources.
 */
static bool peer_is_known(struct ue_ran_transport_ctx *t,
                          const struct sockaddr *sa)
{
    int i;

    pthread_mutex_lock(&t->hb_lock);
    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (t->cells[i].valid && t->cells[i].addr_len > 0 &&
            sa_in_equal((const struct sockaddr *)t->cells[i].addr_storage, sa)) {
            pthread_mutex_unlock(&t->hb_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&t->hb_lock);

    for (i = 0; i < t->gnb_count; i++) {
        struct sockaddr_storage ss;
        socklen_t sl;
        if (resolve_endpoint(t->gnb_list[i].address, t->gnb_list[i].port,
                             &ss, &sl) < 0)
            continue;
        if (sa_in_equal((const struct sockaddr *)&ss, sa))
            return true;
    }
    return false;
}

static int receive_pending(struct ue_ran_transport_ctx *t, uint64_t now_ms)
{
    struct sockaddr_storage peer_addr;
    socklen_t peer_len;
    ssize_t n;
    struct ue_rls_message msg;
    int events = 0;
    int max_per_tick = 64;

    if (t->socket_fd < 0)
        return 0;

    while (max_per_tick-- > 0) {
        peer_len = sizeof(peer_addr);
        n = recvfrom(t->socket_fd, t->rx_buf, sizeof(t->rx_buf), 0,
                     (struct sockaddr *)&peer_addr, &peer_len);

        if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                LOG_ERR(RAN, "recvfrom failed errno=%d", errno);
                return -1;
            }
            break;
        }

        t->rx_bytes += (uint64_t)n;

        LOG_TRC(RAN, "recvfrom %zd bytes from peer", n);

        if (!peer_is_known(t, (struct sockaddr *)&peer_addr)) {
            LOG_TRC(RAN, "drop RLS datagram from unknown peer");
            continue;
        }

        if (ue_rls_decode(t->rx_buf, (size_t)n, &msg) < 0) {
            LOG_TRC(RAN, "RLS decode failed for %zd bytes", n);
            continue;
        }

        switch (msg.type) {
        case UE_RLS_HEARTBEAT_ACK:
            handle_heartbeat_ack(t, &msg.u.heartbeat_ack,
                                (struct sockaddr *)&peer_addr, peer_len,
                                now_ms);
            events++;
            break;

        case UE_RLS_PDU_TRANSMISSION:
            handle_pdu_transmission(t, &msg.u.pdu_tx);
            events++;
            break;

        case UE_RLS_PDU_TRANSMISSION_ACK:
            /* We could remove from a retransmit queue; skip for now */
            events++;
            break;

        default:
            break;
        }
    }

    return events;
}

/* ---- Tick ---- */

int ue_ran_transport_tick(struct ue_ran_transport_ctx *t, uint64_t now_ms)
{
    int events = 0;

    if (!t)
        return -1;
    if (t->state == UE_RAN_TRANSPORT_IDLE)
        return 0;

    /* Expire stale cells */
    expire_cells(t, now_ms);

    /* Heartbeat cycle */
    if (t->last_heartbeat_ms == 0 ||
        now_ms - t->last_heartbeat_ms >= t->heartbeat_interval_ms) {
        send_heartbeats(t, now_ms);
        events++;
    }

    /* Receive pending datagrams */
    {
        int rx = receive_pending(t, now_ms);
        if (rx < 0)
            return -1;
        events += rx;
    }

    /* Send pending ACKs periodically */
    if (t->pending_ack_count > 0 &&
        (t->last_ack_send_ms == 0 ||
         now_ms - t->last_ack_send_ms >= UE_RAN_ACK_SEND_INTERVAL)) {
        send_pending_acks(t, now_ms);
    }

    /* State transitions */
    if (t->state == UE_RAN_TRANSPORT_SEARCHING && t->serving_cell_id >= 0) {
        t->state = UE_RAN_TRANSPORT_CONNECTED;
        LOG_INF(RAN, "connected to cell id=%d", t->serving_cell_id);
    } else if (t->state == UE_RAN_TRANSPORT_CONNECTED && t->serving_cell_id < 0) {
        t->state = UE_RAN_TRANSPORT_LOST;
        LOG_WRN(RAN, "serving cell lost");
    } else if (t->state == UE_RAN_TRANSPORT_LOST && t->serving_cell_id >= 0) {
        t->state = UE_RAN_TRANSPORT_CONNECTED;
        LOG_INF(RAN, "reconnected to cell id=%d", t->serving_cell_id);
    }

    return events;
}

/*
 * Dedicated RLS receive thread: sole reader of the socket. Each iteration runs
 * the transport step (expire/heartbeat/receive/ack/state) and then drains any
 * freshly-queued downlink DATA. This decouples downlink + NAS delivery from the
 * EP0 control loop, whose tick can stall for hundreds of ms on a blocking
 * EVENT_FETCH — which previously gated all user-plane traffic.
 */
static void *ran_rx_worker(void *arg)
{
    struct ue_ran_transport_ctx *t = (struct ue_ran_transport_ctx *)arg;

    while (t->rx_run) {
        struct pollfd pfd;
        int fd;

        pthread_mutex_lock(&t->hb_lock);
        fd = t->socket_fd;
        pthread_mutex_unlock(&t->hb_lock);

        if (fd < 0 || t->state == UE_RAN_TRANSPORT_IDLE) {
            usleep(2000);   /* socket not up yet: idle and recheck */
            continue;
        }

        /* Block until a datagram arrives; cap the wait so timers still fire. */
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        poll(&pfd, 1, 50);

        ue_ran_transport_tick(t, ran_now_ms());

        if (t->on_data_rx)
            t->on_data_rx(t->on_data_rx_ctx);
    }

    return NULL;
}

/* ---- Send NAS PDU ---- */

int ue_ran_transport_send_nas_pdu(struct ue_ran_transport_ctx *t,
                                  const uint8_t *pdu, size_t len,
                                  uint32_t rrc_channel)
{
    struct ue_ran_cell_info *cell;
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    uint8_t txbuf[16384 + 64];
    int enc_len;

    if (!t || !pdu || len == 0)
        return -1;
    if (t->state != UE_RAN_TRANSPORT_CONNECTED || t->serving_cell_id < 0)
        return -1;

    /* Snapshot the serving cell address: the rx thread may mutate the table. */
    pthread_mutex_lock(&t->hb_lock);
    cell = find_cell_by_id(t, t->serving_cell_id);
    if (cell && cell->addr_len > 0 && cell->addr_len <= sizeof(addr)) {
        memcpy(&addr, cell->addr_storage, cell->addr_len);
        addr_len = cell->addr_len;
    }
    pthread_mutex_unlock(&t->hb_lock);
    if (addr_len == 0)
        return -1;

    LOG_TRC(RAN, "send_nas_pdu %zu bytes rrc_ch=%u", len, rrc_channel);

    enc_len = ue_rls_encode_pdu_transmission(txbuf, sizeof(txbuf),
                                             t->sti,
                                             UE_RLS_PDU_TYPE_RRC,
                                             t->next_pdu_id++,
                                             rrc_channel,
                                             pdu, (uint32_t)len);
    if (enc_len <= 0)
        return -1;

    if (send_to_addr(t, (struct sockaddr *)&addr, addr_len,
                     txbuf, (size_t)enc_len) < 0)
        return -1;

    LOG_TRC(RAN, "NAS PDU sent %zu bytes", len);
    t->tx_pdu_count++;
    return 0;
}

/* ---- Send DATA PDU ---- */

int ue_ran_transport_send_data_pdu(struct ue_ran_transport_ctx *t,
                                   int psi,
                                   const uint8_t *data, size_t len)
{
    struct ue_ran_cell_info *cell;
    struct sockaddr_storage addr;
    socklen_t addr_len = 0;
    uint8_t txbuf[16384 + 64];
    int enc_len;

    if (!t || !data || len == 0)
        return -1;
    if (psi < 1 || psi > 15)
        return -1;
    if (t->state != UE_RAN_TRANSPORT_CONNECTED || t->serving_cell_id < 0)
        return -1;

    /*
     * Snapshot the serving cell address under hb_lock. This runs on the uplink
     * data worker thread while the rx thread mutates the cell table.
     */
    pthread_mutex_lock(&t->hb_lock);
    cell = find_cell_by_id(t, t->serving_cell_id);
    if (cell && cell->addr_len > 0 && cell->addr_len <= sizeof(addr)) {
        memcpy(&addr, cell->addr_storage, cell->addr_len);
        addr_len = cell->addr_len;
    }
    pthread_mutex_unlock(&t->hb_lock);
    if (addr_len == 0)
        return -1;

    /*
     * DATA PDUs use pduId=0 (no retransmission tracking).
     * payload = PSI, matching UERANSIM ctl_task.cpp:handleUplinkDataDelivery.
     */
    enc_len = ue_rls_encode_pdu_transmission(txbuf, sizeof(txbuf),
                                             t->sti,
                                             UE_RLS_PDU_TYPE_DATA,
                                             0,
                                             (uint32_t)psi,
                                             data, (uint32_t)len);
    if (enc_len <= 0)
        return -1;

    if (send_to_addr(t, (struct sockaddr *)&addr, addr_len,
                     txbuf, (size_t)enc_len) < 0)
        return -1;

    LOG_TRC(RAN, "DATA PDU sent psi=%d %zu bytes", psi, len);
    t->tx_pdu_count++;
    return 0;
}

/* ---- Receive NAS PDU ---- */

int ue_ran_transport_recv_nas_pdu(struct ue_ran_transport_ctx *t,
                                  uint8_t *buf, size_t buf_len,
                                  uint32_t *rrc_channel_out)
{
    struct ue_ran_rx_entry *e;
    uint32_t copy_len;

    if (!t || !buf || buf_len == 0)
        return -1;

    /* nas_queue is produced by the rx thread; guard the dequeue. */
    pthread_mutex_lock(&t->rx_lock);
    e = rx_queue_peek(t->nas_queue, t->nas_queue_head, t->nas_queue_tail);
    if (!e) {
        pthread_mutex_unlock(&t->rx_lock);
        return 0;
    }

    copy_len = (e->len <= (uint32_t)buf_len) ? e->len : (uint32_t)buf_len;
    memcpy(buf, e->data, copy_len);
    if (rrc_channel_out)
        *rrc_channel_out = e->rrc_channel;
    LOG_TRC(RAN, "NAS PDU recv %u bytes ch=%u", copy_len, e->rrc_channel);
    rx_queue_pop(&t->nas_queue_head);
    pthread_mutex_unlock(&t->rx_lock);

    return (int)copy_len;
}

/* ---- Receive DATA PDU ---- */

int ue_ran_transport_recv_data_pdu(struct ue_ran_transport_ctx *t,
                                   int *psi,
                                   uint8_t *buf, size_t buf_len)
{
    struct ue_ran_rx_entry *e;
    uint32_t copy_len;

    if (!t || !buf || buf_len == 0)
        return -1;

    e = rx_queue_peek(t->data_queue, t->data_queue_head, t->data_queue_tail);
    if (!e)
        return 0;

    copy_len = (e->len <= (uint32_t)buf_len) ? e->len : (uint32_t)buf_len;
    memcpy(buf, e->data, copy_len);
    if (psi)
        *psi = e->psi;
    LOG_TRC(RAN, "DATA PDU recv psi=%d %u bytes", e->psi, copy_len);
    rx_queue_pop(&t->data_queue_head);

    return (int)copy_len;
}

/* ---- Queries ---- */

bool ue_ran_transport_is_connected(const struct ue_ran_transport_ctx *t)
{
    return t && t->state == UE_RAN_TRANSPORT_CONNECTED;
}

int ue_ran_transport_serving_cell_dbm(const struct ue_ran_transport_ctx *t)
{
    int i;

    if (!t || t->serving_cell_id < 0)
        return -999;

    for (i = 0; i < UE_RAN_TRANSPORT_MAX_CELLS; i++) {
        if (t->cells[i].valid && t->cells[i].cell_id == t->serving_cell_id)
            return t->cells[i].dbm;
    }
    return -999;
}
