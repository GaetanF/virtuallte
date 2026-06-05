#ifndef UE_RAN_TRANSPORT_H
#define UE_RAN_TRANSPORT_H

/*
 * ue_ran_transport - Real RAN transport layer toward gNB via RLS protocol.
 *
 * UERANSIM anchor:
 *   - src/ue/rls/udp_task.hpp   : UDP socket, heartbeat, cell tracking
 *   - src/ue/rls/ctl_task.hpp   : PDU ack/retransmission
 *   - src/lib/rls/rls_pdu.hpp   : RLS message types
 *   - src/ue/rrc/task.hpp       : RRC state machine consuming RLS messages
 *
 * This module is the sole owner of the network socket toward the gNB.
 * No other module (ue_mm, ue_sm, state_bridge, mbim_frontend) may open
 * sockets or perform network I/O toward the RAN.
 */

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ue_rls.h"

/*
 * UERANSIM RRC channel values (src/lib/rrc/rrc.hpp).
 * Used as payload in RLS PDU_TRANSMISSION to identify the RRC logical channel.
 */
#define UE_RRC_CHANNEL_BCCH_BCH    0
#define UE_RRC_CHANNEL_BCCH_DL_SCH 1
#define UE_RRC_CHANNEL_DL_CCCH     2
#define UE_RRC_CHANNEL_DL_DCCH     3
#define UE_RRC_CHANNEL_PCCH        4
#define UE_RRC_CHANNEL_UL_CCCH     5
#define UE_RRC_CHANNEL_UL_CCCH1    6
#define UE_RRC_CHANNEL_UL_DCCH     7

/*
 * Transport connection state.
 */
enum ue_ran_transport_state {
    UE_RAN_TRANSPORT_IDLE = 0,       /* no socket, not searching       */
    UE_RAN_TRANSPORT_SEARCHING,      /* heartbeats sent, awaiting ack  */
    UE_RAN_TRANSPORT_CONNECTED,      /* cell found, heartbeat alive    */
    UE_RAN_TRANSPORT_LOST,           /* heartbeat timeout, cell lost   */
};

/*
 * gNB endpoint configuration.
 */
#define UE_RAN_TRANSPORT_MAX_GNB 8

struct ue_ran_gnb_endpoint {
    char address[64];
    uint16_t port;           /* RLS port (default 4997) */
};

/*
 * Cell info tracked from heartbeat ACKs.
 */
#define UE_RAN_TRANSPORT_MAX_CELLS 16

struct ue_ran_cell_info {
    bool valid;
    uint64_t sti;
    int cell_id;
    int dbm;
    uint64_t last_seen_ms;
    /* Resolved sockaddr stored as raw bytes for sendto() */
    uint8_t addr_storage[128];  /* struct sockaddr_in or sockaddr_in6 */
    uint32_t addr_len;
};

/*
 * Receive queue entry for NAS or DATA PDU.
 */
#define UE_RAN_RX_QUEUE_SIZE 32
#define UE_RAN_RX_PDU_MAX   8192

struct ue_ran_rx_entry {
    bool valid;
    enum ue_rls_pdu_type pdu_type;
    int psi;                      /* for DATA PDUs */
    uint32_t rrc_channel;         /* RRC channel type from RLS payload (DL_CCCH=2, DL_DCCH=3) */
    uint8_t data[UE_RAN_RX_PDU_MAX];
    uint32_t len;
};

/*
 * Pending ACK tracking - PDU IDs received that need to be ACKed.
 */
#define UE_RAN_PENDING_ACK_MAX 64

/*
 * Main RAN transport runtime context.
 */
struct ue_ran_transport_ctx {
    enum ue_ran_transport_state state;

    /* gNB search list */
    struct ue_ran_gnb_endpoint gnb_list[UE_RAN_TRANSPORT_MAX_GNB];
    int gnb_count;

    /* Cell tracking */
    struct ue_ran_cell_info cells[UE_RAN_TRANSPORT_MAX_CELLS];
    int cell_count;
    int serving_cell_id;
    int next_cell_id;

    /* UE identity for RLS */
    uint64_t sti;

    /* Real UDP socket */
    int socket_fd;

    /* Heartbeat timing */
    uint64_t last_heartbeat_ms;
    uint32_t heartbeat_interval_ms;
    uint32_t heartbeat_timeout_ms;

    /* PDU ID counter */
    uint32_t next_pdu_id;

    /* Receive queues: separate for NAS (RRC) and DATA */
    struct ue_ran_rx_entry nas_queue[UE_RAN_RX_QUEUE_SIZE];
    int nas_queue_head;
    int nas_queue_tail;

    struct ue_ran_rx_entry data_queue[UE_RAN_RX_QUEUE_SIZE];
    int data_queue_head;
    int data_queue_tail;

    /* Pending ACKs to send back */
    uint32_t pending_ack_ids[UE_RAN_PENDING_ACK_MAX];
    int pending_ack_count;
    uint64_t last_ack_send_ms;

    /* Transmit buffer */
    uint8_t tx_buf[16384 + 64];

    /* Receive buffer (recvfrom fills this) */
    uint8_t rx_buf[16384 + 64];

    /* Statistics */
    uint64_t tx_pdu_count;
    uint64_t rx_pdu_count;
    uint64_t tx_bytes;
    uint64_t rx_bytes;

    /*
     * Dedicated RLS heartbeat thread. Keeps the link alive (sends heartbeats
     * every interval) even when the engine main-thread tick stalls on a
     * blocking EP0 transfer, which would otherwise let the gNB time us out
     * ("signal lost"). hb_lock guards socket_fd/state access shared with it.
     */
    pthread_mutex_t hb_lock;
    pthread_t       hb_thread;
    bool            hb_thread_started;
    bool            hb_run;

    /*
     * Dedicated RLS receive thread. Sole reader of socket_fd: it decodes every
     * incoming RLS datagram off the engine main thread, so downlink data and
     * NAS are no longer gated by the (frequently blocked) EP0 control loop.
     *
     * Locking after this change:
     *   - hb_lock guards socket_fd, state AND the cell table
     *     (cells[]/cell_count/serving_cell_id/next_cell_id), which the rx thread
     *     writes and the sender threads (NAS on EP0, DATA on the uplink worker)
     *     read.
     *   - rx_lock guards nas_queue, produced by the rx thread and consumed by
     *     the engine main thread.
     *   - data_queue and pending_ack_* stay single-threaded on the rx thread.
     *   - tx_buf is only touched by the rx thread (acks/heartbeats); the NAS and
     *     DATA senders encode into their own local buffers.
     */
    pthread_mutex_t rx_lock;
    pthread_t       rx_thread;
    bool            rx_thread_started;
    bool            rx_run;

    /* Invoked on the rx thread after each receive batch to drain DATA PDUs. */
    void          (*on_data_rx)(void *ctx);
    void           *on_data_rx_ctx;
};

void ue_ran_transport_init(struct ue_ran_transport_ctx *t);

int ue_ran_transport_configure(struct ue_ran_transport_ctx *t,
                               const char *gnb_addresses[],
                               int count,
                               uint16_t default_port);

int ue_ran_transport_add_gnb(struct ue_ran_transport_ctx *t,
                             const char *address,
                             uint16_t port);

int ue_ran_transport_start(struct ue_ran_transport_ctx *t);
void ue_ran_transport_stop(struct ue_ran_transport_ctx *t);
void ue_ran_transport_refresh_sti(struct ue_ran_transport_ctx *t);
void ue_ran_transport_deinit(struct ue_ran_transport_ctx *t);

int ue_ran_transport_tick(struct ue_ran_transport_ctx *t, uint64_t now_ms);

/*
 * Register a callback invoked on the dedicated rx thread right after each
 * receive batch, used to drain freshly-queued downlink DATA PDUs without
 * waiting for the engine main-thread tick.
 */
void ue_ran_transport_set_data_rx_cb(struct ue_ran_transport_ctx *t,
                                     void (*cb)(void *), void *ctx);

int ue_ran_transport_send_nas_pdu(struct ue_ran_transport_ctx *t,
                                  const uint8_t *pdu, size_t len,
                                  uint32_t rrc_channel);

int ue_ran_transport_send_data_pdu(struct ue_ran_transport_ctx *t,
                                   int psi,
                                   const uint8_t *data, size_t len);

int ue_ran_transport_recv_nas_pdu(struct ue_ran_transport_ctx *t,
                                  uint8_t *buf, size_t buf_len,
                                  uint32_t *rrc_channel_out);

int ue_ran_transport_recv_data_pdu(struct ue_ran_transport_ctx *t,
                                   int *psi,
                                   uint8_t *buf, size_t buf_len);

bool ue_ran_transport_is_connected(const struct ue_ran_transport_ctx *t);
int ue_ran_transport_serving_cell_dbm(const struct ue_ran_transport_ctx *t);

#endif
