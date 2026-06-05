#include "ims_service.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <sys/random.h>

#include "../common/log.h"
#include "../ue_engine/ue_nas_security.h"
#include "ims_digest.h"
#include "ims_ip.h"
#include "ims_rpdata.h"

#define IMS_SMS_QUEUE_SIZE 16
#define IMS_SMS_PDU_MAX    512
#define IMS_IP_QUEUE_SIZE  32
#define IMS_IP_PACKET_MAX  2048
#define IMS_SIP_LOCAL_PORT 5062
#define IMS_SIP_REMOTE_PORT 5060
#define IMS_REGISTER_EXPIRES_SECONDS 600u
#define IMS_REGISTER_REFRESH_MARGIN_SECONDS 60u
/* Retransmit an unanswered initial REGISTER (SIP/UDP has no transport ACK). */
#define IMS_REGISTER_RETRY_MS    4000u
#define IMS_REGISTER_MAX_ATTEMPTS 5

struct ims_sms_item {
    uint32_t reference;
    uint8_t pdu[IMS_SMS_PDU_MAX];
    size_t pdu_len;
};

struct ims_ip_item {
    int psi;
    uint8_t packet[IMS_IP_PACKET_MAX];
    size_t packet_len;
};

struct sip_auth_challenge {
    char realm[128];
    char nonce[512];
    char algorithm[32];
    char qop[32];
};

struct ims_service {
    bool enabled;
    bool sms_enabled;
    bool running;
    bool registered;
    bool pdu_active;
    bool has_pcscf;
    bool register_sent;
    bool register_auth_valid;
    uint64_t register_refresh_ms;
    uint64_t register_sent_ms;   /* when the last (initial/auth) REGISTER was sent */
    int register_attempts;       /* bounded retransmissions of the initial REGISTER */
    uint8_t ipv4[4];
    uint8_t pcscf_ipv4[4];
    ims_service_tx_ip_cb tx_cb;
    void *tx_cb_data;
    ims_service_sms_downlink_cb sms_dl_cb;
    void *sms_dl_cb_data;
    uint32_t next_sms_reference;
    uint32_t next_sip_cseq;
    char realm[96];
    char impi[160];
    char impu_user[64];
    char preferred_impu[180];
    char sim_key[64];
    char sim_opc[64];
    char sim_amf[16];
    struct sip_auth_challenge register_auth;

    /* Last delivered MT RPDU, to drop duplicate host delivery when the SMSC
     * retransmits an un-acked SMS (worker-thread only, no lock needed). */
    uint8_t last_mt_rpdu[256];
    size_t  last_mt_rpdu_len;

    pthread_t thread;
    bool thread_started;
    pthread_mutex_t lock;
    pthread_cond_t cond;

    struct ims_sms_item sms_queue[IMS_SMS_QUEUE_SIZE];
    int sms_head;
    int sms_tail;

    struct ims_ip_item ip_queue[IMS_IP_QUEUE_SIZE];
    int ip_head;
    int ip_tail;
};

static int mnc3_value(const char *mnc)
{
    if (!mnc || mnc[0] == '\0')
        return 0;
    return atoi(mnc);
}

static uint64_t ims_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* Fill `out` (NUL-terminated) with random lowercase hex from the kernel CSPRNG. */
static void ims_random_hex(char *out, size_t out_sz)
{
    uint8_t b[8];
    size_t i;

    if (out_sz == 0)
        return;
    if (getentropy(b, sizeof(b)) != 0) {
        /* Fallback: still better than a constant. */
        for (i = 0; i < sizeof(b); i++)
            b[i] = (uint8_t)(rand() ^ (int)ims_now_ms());
    }
    for (i = 0; i < sizeof(b) && (i * 2 + 2) < out_sz; i++)
        snprintf(out + i * 2, out_sz - i * 2, "%02x", b[i]);
}

static void realtime_from_monotonic_deadline(uint64_t mono_deadline_ms,
                                             struct timespec *out)
{
    uint64_t now_ms = ims_now_ms();
    uint64_t delta_ms = mono_deadline_ms > now_ms ? mono_deadline_ms - now_ms : 0;
    struct timespec rt;

    clock_gettime(CLOCK_REALTIME, &rt);
    rt.tv_sec += (time_t)(delta_ms / 1000u);
    rt.tv_nsec += (long)((delta_ms % 1000u) * 1000000u);
    if (rt.tv_nsec >= 1000000000L) {
        rt.tv_sec++;
        rt.tv_nsec -= 1000000000L;
    }
    *out = rt;
}

static void ims_build_identity(struct ims_service *svc,
                               const struct ue_instance_config *cfg)
{
    int mnc = mnc3_value(cfg->network.mnc);

    snprintf(svc->realm, sizeof(svc->realm),
             "ims.mnc%03d.mcc%03d.3gppnetwork.org",
             mnc, atoi(cfg->network.mcc));
    snprintf(svc->impi, sizeof(svc->impi), "%s@%s", cfg->sim.imsi, svc->realm);
    snprintf(svc->impu_user, sizeof(svc->impu_user), "%s", cfg->sim.imsi);

    snprintf(svc->preferred_impu, sizeof(svc->preferred_impu),
             "sip:%s@%s", svc->impu_user, svc->realm);
    snprintf(svc->sim_key, sizeof(svc->sim_key), "%s", cfg->sim.key);
    snprintf(svc->sim_opc, sizeof(svc->sim_opc), "%s", cfg->sim.opc);
    snprintf(svc->sim_amf, sizeof(svc->sim_amf), "%s", cfg->sim.amf);
}

static int ims_build_contact_uri(char *out, size_t out_len,
                                 const struct ims_service *svc,
                                 const uint8_t local_ip[4])
{
    int n;

    if (!out || !svc || !local_ip)
        return -EINVAL;

    n = snprintf(out, out_len,
                 "sip:%s@%u.%u.%u.%u:%u",
                 svc->impu_user,
                 local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                 IMS_SIP_LOCAL_PORT);

    if (n <= 0 || (size_t)n >= out_len)
        return -EMSGSIZE;

    return 0;
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + c - 'a';
    if (c >= 'A' && c <= 'F')
        return 10 + c - 'A';
    return -1;
}

static int parse_hex_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    size_t i;

    if (!hex || !out || strlen(hex) < out_len * 2)
        return -EINVAL;
    for (i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -EINVAL;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static int base64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + c - 'a';
    if (c >= '0' && c <= '9') return 52 + c - '0';
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int base64_decode(const char *in, uint8_t *out, size_t out_cap)
{
    int val = 0;
    int bits = -8;
    size_t pos = 0;

    if (!in || !out)
        return -EINVAL;
    for (; *in; in++) {
        int v;

        if (*in == '=')
            break;
        v = base64_val(*in);
        if (v < 0)
            continue;
        val = (val << 6) | v;
        bits += 6;
        if (bits >= 0) {
            if (pos >= out_cap)
                return -EMSGSIZE;
            out[pos++] = (uint8_t)((val >> bits) & 0xff);
            bits -= 8;
        }
    }
    return (int)pos;
}

static bool sms_queue_empty(const struct ims_service *svc)
{
    return svc->sms_head == svc->sms_tail;
}

static bool sms_queue_full(const struct ims_service *svc)
{
    return ((svc->sms_tail + 1) % IMS_SMS_QUEUE_SIZE) == svc->sms_head;
}

static bool ip_queue_empty(const struct ims_service *svc)
{
    return svc->ip_head == svc->ip_tail;
}

static bool ip_queue_full(const struct ims_service *svc)
{
    return ((svc->ip_tail + 1) % IMS_IP_QUEUE_SIZE) == svc->ip_head;
}

static bool sms_queue_pop_locked(struct ims_service *svc, struct ims_sms_item *out)
{
    if (sms_queue_empty(svc))
        return false;
    *out = svc->sms_queue[svc->sms_head];
    svc->sms_head = (svc->sms_head + 1) % IMS_SMS_QUEUE_SIZE;
    return true;
}

static bool ip_queue_pop_locked(struct ims_service *svc, struct ims_ip_item *out)
{
    if (ip_queue_empty(svc))
        return false;
    *out = svc->ip_queue[svc->ip_head];
    svc->ip_head = (svc->ip_head + 1) % IMS_IP_QUEUE_SIZE;
    return true;
}

static char sms_addr_digit(uint8_t semi, bool high)
{
    uint8_t v = high ? (uint8_t)(semi >> 4) : (uint8_t)(semi & 0x0f);

    if (v <= 9)
        return (char)('0' + v);
    if (v == 0x0a)
        return '*';
    if (v == 0x0b)
        return '#';
    return '\0';
}

static bool ims_sms_extract_destination(const uint8_t *pdu, size_t pdu_len,
                                        char *out, size_t out_len)
{
    size_t tpdu = 0;
    uint8_t da_len;
    uint8_t toa;
    size_t da_octets;
    size_t pos = 0;
    size_t i;

    if (!pdu || !out || out_len < 4 || pdu_len < 5)
        return false;

    if ((size_t)pdu[0] + 1 < pdu_len)
        tpdu = (size_t)pdu[0] + 1;

    if (tpdu + 4 > pdu_len)
        return false;
    if ((pdu[tpdu] & 0x03) != 0x01)
        return false;

    da_len = pdu[tpdu + 2];
    toa = pdu[tpdu + 3];
    da_octets = (da_len + 1u) / 2u;
    if (da_len == 0 || tpdu + 4 + da_octets > pdu_len)
        return false;

    if ((toa & 0x70) == 0x10 && pos + 1 < out_len)
        out[pos++] = '+';

    for (i = 0; i < da_len && pos + 1 < out_len; i++) {
        char d = sms_addr_digit(pdu[tpdu + 4 + i / 2], (i & 1u) != 0);
        if (!d)
            return false;
        out[pos++] = d;
    }
    out[pos] = '\0';
    return pos > 0;
}

static const uint8_t *find_bytes(const uint8_t *data, size_t len,
                                 const char *needle, size_t needle_len)
{
    size_t i;

    if (!data || !needle || needle_len == 0 || len < needle_len)
        return NULL;
    for (i = 0; i + needle_len <= len; i++) {
        if (!memcmp(data + i, needle, needle_len))
            return data + i;
    }
    return NULL;
}

static int ascii_lower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

static const char *find_ascii_case(const char *haystack, const char *needle)
{
    size_t needle_len;

    if (!haystack || !needle)
        return NULL;
    needle_len = strlen(needle);
    if (needle_len == 0)
        return haystack;
    for (; *haystack; haystack++) {
        size_t i;
        for (i = 0; i < needle_len; i++) {
            if (!haystack[i] || ascii_lower((unsigned char)haystack[i]) !=
                ascii_lower((unsigned char)needle[i]))
                break;
        }
        if (i == needle_len)
            return haystack;
    }
    return NULL;
}

static bool header_has_content_type_sms(const uint8_t *hdr, size_t hdr_len)
{
    const uint8_t *line = hdr;
    const uint8_t *end = hdr + hdr_len;

    while (line < end) {
        const uint8_t *next = find_bytes(line, (size_t)(end - line), "\r\n", 2);
        size_t line_len = next ? (size_t)(next - line) : (size_t)(end - line);

        if (line_len > 13 && !strncasecmp((const char *)line, "Content-Type:", 13) &&
            find_bytes(line, line_len, "application/vnd.3gpp.sms", 24))
            return true;
        if (!next)
            break;
        line = next + 2;
    }
    return false;
}

static bool header_get_content_length(const uint8_t *hdr, size_t hdr_len,
                                      size_t *out_len)
{
    const uint8_t *line = hdr;
    const uint8_t *end = hdr + hdr_len;

    if (out_len)
        *out_len = 0;
    while (line < end) {
        const uint8_t *next = find_bytes(line, (size_t)(end - line), "\r\n", 2);
        size_t line_len = next ? (size_t)(next - line) : (size_t)(end - line);

        if (line_len > 15 && !strncasecmp((const char *)line, "Content-Length:", 15)) {
            size_t i;
            size_t v = 0;

            for (i = 15; i < line_len && (line[i] == ' ' || line[i] == '\t'); i++)
                ;
            if (i == line_len || line[i] < '0' || line[i] > '9')
                return false;
            for (; i < line_len && line[i] >= '0' && line[i] <= '9'; i++)
                v = v * 10u + (size_t)(line[i] - '0');
            *out_len = v;
            return true;
        }
        if (!next)
            break;
        line = next + 2;
    }
    return false;
}

static bool header_get_uint(const uint8_t *hdr, size_t hdr_len,
                            const char *name, uint32_t *out)
{
    const uint8_t *line = hdr;
    const uint8_t *end = hdr + hdr_len;
    size_t name_len = strlen(name);

    if (out)
        *out = 0;
    while (line < end) {
        const uint8_t *next = find_bytes(line, (size_t)(end - line), "\r\n", 2);
        size_t line_len = next ? (size_t)(next - line) : (size_t)(end - line);

        if (line_len > name_len && !strncasecmp((const char *)line, name, name_len)) {
            size_t i;
            uint32_t v = 0;

            for (i = name_len; i < line_len && (line[i] == ' ' || line[i] == '\t'); i++)
                ;
            if (i == line_len || line[i] < '0' || line[i] > '9')
                return false;
            for (; i < line_len && line[i] >= '0' && line[i] <= '9'; i++)
                v = v * 10u + (uint32_t)(line[i] - '0');
            if (out)
                *out = v;
            return true;
        }
        if (!next)
            break;
        line = next + 2;
    }
    return false;
}

static bool header_has_cseq_method(const uint8_t *hdr, size_t hdr_len,
                                   const char *method)
{
    const uint8_t *line = hdr;
    const uint8_t *end = hdr + hdr_len;
    size_t method_len = strlen(method);

    while (line < end) {
        const uint8_t *next = find_bytes(line, (size_t)(end - line), "\r\n", 2);
        size_t line_len = next ? (size_t)(next - line) : (size_t)(end - line);

        if (line_len > 5 && !strncasecmp((const char *)line, "CSeq:", 5) &&
            find_bytes(line, line_len, method, method_len))
            return true;
        if (!next)
            break;
        line = next + 2;
    }
    return false;
}

static bool header_copy_line(const uint8_t *hdr, size_t hdr_len,
                             const char *name,
                             char *out, size_t out_len)
{
    const uint8_t *line = hdr;
    const uint8_t *end = hdr + hdr_len;
    size_t name_len = strlen(name);

    if (!out || out_len == 0)
        return false;
    out[0] = '\0';

    while (line < end) {
        const uint8_t *next = find_bytes(line, (size_t)(end - line), "\r\n", 2);
        size_t line_len = next ? (size_t)(next - line) : (size_t)(end - line);

        if (line_len > name_len && !strncasecmp((const char *)line, name, name_len)) {
            if (line_len >= out_len)
                line_len = out_len - 1;
            memcpy(out, line, line_len);
            out[line_len] = '\0';
            return true;
        }
        if (!next)
            break;
        line = next + 2;
    }
    return false;
}

static bool auth_param_copy(const char *line, const char *name,
                            char *out, size_t out_len)
{
    const char *p = line;
    size_t name_len = strlen(name);

    if (!line || !out || out_len == 0)
        return false;
    out[0] = '\0';
    while ((p = find_ascii_case(p, name)) != NULL) {
        const char *v;
        size_t len = 0;

        if (p != line && p[-1] != ' ' && p[-1] != ',' && p[-1] != '\t') {
            p += name_len;
            continue;
        }
        v = p + name_len;
        while (*v == ' ' || *v == '\t')
            v++;
        if (*v != '=') {
            p += name_len;
            continue;
        }
        v++;
        while (*v == ' ' || *v == '\t')
            v++;
        if (*v == '"') {
            v++;
            while (v[len] && v[len] != '"')
                len++;
        } else {
            while (v[len] && v[len] != ',' && v[len] != ' ' && v[len] != '\t' &&
                   v[len] != '\r' && v[len] != '\n')
                len++;
        }
        if (len >= out_len)
            len = out_len - 1;
        memcpy(out, v, len);
        out[len] = '\0';
        return len > 0;
    }
    return false;
}

static bool parse_www_authenticate(const uint8_t *hdr, size_t hdr_len,
                                   struct sip_auth_challenge *out)
{
    char line[1024];

    if (!out || !header_copy_line(hdr, hdr_len, "WWW-Authenticate:", line, sizeof(line)))
        return false;
    memset(out, 0, sizeof(*out));
    if (!find_ascii_case(line, "Digest"))
        return false;
    if (!auth_param_copy(line, "realm", out->realm, sizeof(out->realm)))
        return false;
    if (!auth_param_copy(line, "nonce", out->nonce, sizeof(out->nonce)))
        return false;
    if (!auth_param_copy(line, "algorithm", out->algorithm, sizeof(out->algorithm)))
        snprintf(out->algorithm, sizeof(out->algorithm), "%s", "MD5");
    if (!auth_param_copy(line, "qop", out->qop, sizeof(out->qop)))
        out->qop[0] = '\0';
    if (find_ascii_case(out->qop, "auth"))
        snprintf(out->qop, sizeof(out->qop), "%s", "auth");
    return true;
}

static bool ims_compute_aka_res(struct ims_service *svc,
                                const char *nonce,
                                uint8_t res[8])
{
    uint8_t decoded[256];
    uint8_t k[16];
    uint8_t opc[16];
    uint8_t amf[2];
    uint8_t sqn[6];
    struct ue_milenage_result tmp;
    int len;
    int i;

    len = base64_decode(nonce, decoded, sizeof(decoded));
    if (len < 32)
        return false;
    if (parse_hex_bytes(svc->sim_key, k, sizeof(k)) < 0 ||
        parse_hex_bytes(svc->sim_opc, opc, sizeof(opc)) < 0 ||
        parse_hex_bytes(svc->sim_amf, amf, sizeof(amf)) < 0)
        return false;

    memset(sqn, 0, sizeof(sqn));
    if (ue_milenage_compute(opc, k, decoded, sqn, amf, &tmp) < 0)
        return false;
    for (i = 0; i < 6; i++)
        sqn[i] = decoded[16 + i] ^ tmp.ak[i];
    if (ue_milenage_compute(opc, k, decoded, sqn, amf, &tmp) < 0)
        return false;
    if (memcmp(tmp.mac_a, decoded + 24, 8) != 0)
        return false;
    memcpy(res, tmp.res, 8);
    return true;
}

/*
 * Copy every header line matching `name` (including the field name), each
 * CRLF-terminated, into out. A SIP response MUST echo the *entire* Via stack
 * (one per traversed proxy) for the response to route back; copying only the
 * top Via breaks routing through the P-CSCF/S-CSCF/IP-SM-GW chain.
 * Returns the number of lines copied.
 */
static int header_copy_all_lines(const uint8_t *hdr, size_t hdr_len,
                                 const char *name, char *out, size_t out_cap)
{
    const uint8_t *line = hdr;
    const uint8_t *end = hdr + hdr_len;
    size_t name_len = strlen(name);
    size_t used = 0;
    int count = 0;

    if (out && out_cap)
        out[0] = '\0';
    while (line < end) {
        const uint8_t *next = find_bytes(line, (size_t)(end - line), "\r\n", 2);
        size_t line_len = next ? (size_t)(next - line) : (size_t)(end - line);

        if (line_len > name_len &&
            !strncasecmp((const char *)line, name, name_len)) {
            if (used + line_len + 3 <= out_cap) {
                memcpy(out + used, line, line_len);
                used += line_len;
                out[used++] = '\r';
                out[used++] = '\n';
                out[used] = '\0';
                count++;
            }
        }
        if (!next)
            break;
        line = next + 2;
    }
    return count;
}

static void ims_send_sip_message_ok(struct ims_service *svc,
                                    const uint8_t *hdr,
                                    size_t hdr_len)
{
    char vias[768];
    char from[256];
    char to[288];
    char call_id[256];
    char cseq[128];
    char sip[2048];
    uint8_t packet[2200];
    uint8_t local_ip[4];
    uint8_t pcscf_ip[4];
    ims_service_tx_ip_cb tx_cb;
    void *tx_cb_data;
    int sip_len;
    int packet_len;

    if (header_copy_all_lines(hdr, hdr_len, "Via:", vias, sizeof(vias)) == 0 ||
        !header_copy_line(hdr, hdr_len, "From:", from, sizeof(from)) ||
        !header_copy_line(hdr, hdr_len, "To:", to, sizeof(to)) ||
        !header_copy_line(hdr, hdr_len, "Call-ID:", call_id, sizeof(call_id)) ||
        !header_copy_line(hdr, hdr_len, "CSeq:", cseq, sizeof(cseq)))
        return;

    /* UAS adds a To-tag when the request carried none (RFC 3261 §8.2.6.2). */
    if (!strstr(to, "tag=")) {
        size_t l = strlen(to);
        snprintf(to + l, sizeof(to) - l, ";tag=virtlte-mt");
    }

    pthread_mutex_lock(&svc->lock);
    if (!svc->pdu_active || !svc->has_pcscf || !svc->tx_cb) {
        pthread_mutex_unlock(&svc->lock);
        return;
    }
    memcpy(local_ip, svc->ipv4, 4);
    memcpy(pcscf_ip, svc->pcscf_ipv4, 4);
    tx_cb = svc->tx_cb;
    tx_cb_data = svc->tx_cb_data;
    pthread_mutex_unlock(&svc->lock);

    sip_len = snprintf(sip, sizeof(sip),
                       "SIP/2.0 200 OK\r\n"
                       "%s"                 /* all Via lines, each CRLF-terminated */
                       "%s\r\n%s\r\n%s\r\n%s\r\n"
                       "Content-Length: 0\r\n\r\n",
                       vias, from, to, call_id, cseq);
    if (sip_len <= 0 || (size_t)sip_len >= sizeof(sip))
        return;

    packet_len = ims_ip_build_udp_ipv4(packet, sizeof(packet),
                                       local_ip, pcscf_ip,
                                       IMS_SIP_LOCAL_PORT,
                                       IMS_SIP_REMOTE_PORT,
                                       (const uint8_t *)sip,
                                       (size_t)sip_len);
    if (packet_len > 0)
        (void)tx_cb(packet, (size_t)packet_len, tx_cb_data);
}

/*
 * Parse a mobile-terminated RP-DATA (Network->MS) RPDU and rebuild the 27.005
 * PDU the host expects via SMS_READ: [SCA-len][SCA][TPDU], where the SCA is
 * taken from RP-OA (the originating SMSC) and the TPDU from RP-UD.
 *   RP-MTI(1) | RP-MR(1) | RP-OA(LV) | RP-DA(LV) | RP-UD(LV = TPDU)
 * Returns the MBIM PDU length and the RP-MR (to echo in the RP-ACK), or -1.
 */
/* ims_rp_data_to_mbim_pdu(): moved to ims_rpdata.c (unit-tested in isolation). */

/* Copy the addr-spec inside <...> from a SIP header value line. */
static void ims_extract_angle_uri(const char *line, char *out, size_t cap)
{
    const char *lt = line ? strchr(line, '<') : NULL;
    const char *gt = lt ? strchr(lt, '>') : NULL;

    out[0] = '\0';
    if (lt && gt && gt > lt + 1) {
        size_t n = (size_t)(gt - lt - 1);
        if (n >= cap)
            n = cap - 1;
        memcpy(out, lt + 1, n);
        out[n] = '\0';
    }
}

/*
 * Send a mobile-originated RP-ACK (TS 24.011) in a new SIP MESSAGE back toward
 * the originator (SMSC/IP-SM-GW), acknowledging a received RP-DATA at the SMS
 * relay layer. Body: RP-MTI(0x02 = RP-ACK MS->N) | RP-MR (echoed).
 */
static void ims_send_rp_ack(struct ims_service *svc,
                            const uint8_t *recv_hdr, size_t recv_hdr_len,
                            uint8_t rp_mr)
{
    char from_line[256];
    char orig_uri[200];
    char header[768];
    uint8_t rpack[6];
    uint8_t sip[1024];
    uint8_t packet[1280];
    uint8_t local_ip[4];
    uint8_t pcscf_ip[4];
    ims_service_tx_ip_cb tx_cb;
    void *tx_cb_data;
    uint32_t cseq;
    int header_len;
    int packet_len;

    if (!header_copy_line(recv_hdr, recv_hdr_len, "From:", from_line, sizeof(from_line)))
        return;
    ims_extract_angle_uri(from_line, orig_uri, sizeof(orig_uri));
    if (orig_uri[0] == '\0')
        return;

    pthread_mutex_lock(&svc->lock);
    if (!svc->pdu_active || !svc->has_pcscf || !svc->tx_cb) {
        pthread_mutex_unlock(&svc->lock);
        return;
    }
    memcpy(local_ip, svc->ipv4, 4);
    memcpy(pcscf_ip, svc->pcscf_ipv4, 4);
    tx_cb = svc->tx_cb;
    tx_cb_data = svc->tx_cb_data;
    cseq = svc->next_sip_cseq++;
    pthread_mutex_unlock(&svc->lock);

    /*
     * RP-ACK (MS -> Network) carrying a minimal SMS-DELIVER-REPORT in RP-User
     * Data. Many IP-SM-GWs ignore a bare RP-ACK (no RP-UD) and keep retransmit-
     * ting; the DELIVER-REPORT is the SMS transfer-layer acknowledgement.
     *   02 | MR | 41 (RP-UD IEI) | 02 (len) | 00 (DELIVER-REPORT: TP-MTI=0) | 00 (TP-PI=0)
     */
    rpack[0] = 0x02;        /* RP-MTI: RP-ACK (MS -> Network) */
    rpack[1] = rp_mr;       /* echo the received RP-Message Reference */
    rpack[2] = 0x41;        /* RP-User-Data IEI */
    rpack[3] = 0x02;        /* RP-UD length */
    rpack[4] = 0x00;        /* SMS-DELIVER-REPORT: TP-MTI=0, no UDHI */
    rpack[5] = 0x00;        /* TP-PI = 0 (no optional parameters) */

    header_len = snprintf(header, sizeof(header),
                          "MESSAGE %s SIP/2.0\r\n"
                          "Via: SIP/2.0/UDP %u.%u.%u.%u:%u;branch=z9hG4bK-virtlte-rpack-%u\r\n"
                          "Max-Forwards: 70\r\n"
                          "From: <%s>;tag=virtlte-sms\r\n"
                          "To: <%s>\r\n"
                          "Call-ID: virtlte-rpack-%u@%u.%u.%u.%u\r\n"
                          "CSeq: %u MESSAGE\r\n"
                          "Content-Type: application/vnd.3gpp.sms\r\n"
                          "Content-Length: %d\r\n\r\n",
                          orig_uri,
                          local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                          IMS_SIP_LOCAL_PORT, cseq,
                          svc->preferred_impu,
                          orig_uri,
                          cseq, local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                          cseq,
                          (int)sizeof(rpack));
    if (header_len <= 0 ||
        (size_t)header_len + sizeof(rpack) > sizeof(sip))
        return;

    memcpy(sip, header, (size_t)header_len);
    memcpy(sip + header_len, rpack, sizeof(rpack));

    packet_len = ims_ip_build_udp_ipv4(packet, sizeof(packet), local_ip, pcscf_ip,
                                       IMS_SIP_LOCAL_PORT, IMS_SIP_REMOTE_PORT,
                                       sip, (size_t)header_len + sizeof(rpack));
    if (packet_len > 0) {
        (void)tx_cb(packet, (size_t)packet_len, tx_cb_data);
        LOG_INF(IMS, "IMS SMS RP-ACK sent (mr=%u)", rp_mr);
    }
}

static void ims_handle_sip_message(struct ims_service *svc,
                                   const uint8_t *payload,
                                   size_t payload_len)
{
    const uint8_t *body;
    const uint8_t *hdr_end;
    size_t hdr_len;
    size_t content_len;
    ims_service_sms_downlink_cb cb;
    void *cb_data;
    uint8_t mbim_pdu[IMS_SMS_PDU_MAX + 16];
    int mbim_len;
    uint8_t rp_mr = 0;

    if (payload_len < 8 || memcmp(payload, "MESSAGE ", 8))
        return;

    hdr_end = find_bytes(payload, payload_len, "\r\n\r\n", 4);
    if (!hdr_end)
        return;
    hdr_len = (size_t)(hdr_end - payload);
    body = hdr_end + 4;

    if (!header_has_content_type_sms(payload, hdr_len))
        return;
    if (!header_get_content_length(payload, hdr_len, &content_len))
        return;
    if (content_len == 0 || content_len > payload_len - (size_t)(body - payload))
        return;

    /* Always acknowledge the SIP transaction. */
    ims_send_sip_message_ok(svc, payload, hdr_len);

    /*
     * Only RP-DATA (n->ms) carries an SMS for the host. RP-ACK/RP-ERROR (the
     * network's response to our MO) is acknowledged at SIP level above and
     * otherwise ignored here.
     */
    if ((body[0] & 0x07) != 0x01) {
        LOG_DBG(IMS, "IMS SMS MT: non-RP-DATA body (mti=%u), SIP-acked only",
                body[0] & 0x07);
        return;
    }

    mbim_len = ims_rp_data_to_mbim_pdu(body, content_len,
                                       mbim_pdu, sizeof(mbim_pdu), &rp_mr);
    if (mbim_len <= 0) {
        LOG_WRN(IMS, "IMS SMS MT: RP-DATA parse failed len=%zu", content_len);
        return;
    }

    /*
     * SMSC retransmits an un-acknowledged SMS (~every 30s) with the identical
     * RPDU. Drop the duplicate host delivery but still re-send the RP-ACK — the
     * retransmission means our previous RP-ACK did not reach the network.
     */
    if (content_len <= sizeof(svc->last_mt_rpdu) &&
        content_len == svc->last_mt_rpdu_len &&
        memcmp(body, svc->last_mt_rpdu, content_len) == 0) {
        LOG_INF(IMS, "IMS SMS MT duplicate (retransmit), re-ACK only");
        ims_send_rp_ack(svc, payload, hdr_len, rp_mr);
        return;
    }
    if (content_len <= sizeof(svc->last_mt_rpdu)) {
        memcpy(svc->last_mt_rpdu, body, content_len);
        svc->last_mt_rpdu_len = content_len;
    }

    pthread_mutex_lock(&svc->lock);
    cb = svc->sms_dl_cb;
    cb_data = svc->sms_dl_cb_data;
    pthread_mutex_unlock(&svc->lock);

    if (cb && cb(mbim_pdu, (size_t)mbim_len, cb_data) == 0)
        LOG_INF(IMS, "IMS SMS received (MT) %d bytes", mbim_len);

    /* SMS relay-layer acknowledgement back to the network. */
    ims_send_rp_ack(svc, payload, hdr_len, rp_mr);
}

static bool register_needed_locked(const struct ims_service *svc)
{
    return svc->enabled && svc->pdu_active && svc->has_pcscf &&
           !svc->registered && !svc->register_sent;
}

static bool register_refresh_needed_locked(const struct ims_service *svc,
                                           uint64_t now_ms)
{
    return svc->enabled && svc->pdu_active && svc->has_pcscf &&
           svc->registered &&
           svc->register_refresh_ms > 0 && now_ms >= svc->register_refresh_ms;
}

/* An initial REGISTER was sent but no response arrived within the retry window
 * (and we have attempts left): time to retransmit. */
static bool register_retry_needed_locked(const struct ims_service *svc,
                                         uint64_t now_ms)
{
    return svc->enabled && svc->pdu_active && svc->has_pcscf &&
           !svc->registered && svc->register_sent &&
           svc->register_sent_ms > 0 &&
           svc->register_attempts < IMS_REGISTER_MAX_ATTEMPTS &&
           now_ms >= svc->register_sent_ms + IMS_REGISTER_RETRY_MS;
}

/* Earliest deadline the worker must wake for: REGISTER refresh or retry. */
static bool next_register_refresh_deadline_locked(const struct ims_service *svc,
                                                  uint64_t *deadline_ms)
{
    bool have = false;
    uint64_t best = 0;

    if (!deadline_ms)
        return false;

    if (svc->enabled && svc->pdu_active && svc->has_pcscf &&
        svc->registered && svc->register_refresh_ms > 0) {
        best = svc->register_refresh_ms;
        have = true;
    }

    if (svc->enabled && svc->pdu_active && svc->has_pcscf &&
        !svc->registered && svc->register_sent && svc->register_sent_ms > 0 &&
        svc->register_attempts < IMS_REGISTER_MAX_ATTEMPTS) {
        uint64_t retry = svc->register_sent_ms + IMS_REGISTER_RETRY_MS;
        if (!have || retry < best) {
            best = retry;
            have = true;
        }
    }

    if (have)
        *deadline_ms = best;
    return have;
}

static int ims_send_authorized_register(struct ims_service *svc,
                                        const struct sip_auth_challenge *challenge);

static void ims_handle_rx_ip(struct ims_service *svc,
                             const struct ims_ip_item *item)
{
    struct ims_udp_packet udp;

    if (ims_ip_parse_udp_ipv4(item->packet, item->packet_len, &udp) < 0)
        return;
    if (udp.src_port != IMS_SIP_REMOTE_PORT || udp.dst_port != IMS_SIP_LOCAL_PORT)
        return;

    LOG_TRC(IMS, "IMS SIP RX len=%zu", udp.payload_len);

    ims_handle_sip_message(svc, udp.payload, udp.payload_len);

    if (udp.payload_len >= 11 && !memcmp(udp.payload, "SIP/2.0 200", 11) &&
        header_has_cseq_method(udp.payload, udp.payload_len, "REGISTER")) {
        uint32_t expires = IMS_REGISTER_EXPIRES_SECONDS;
        uint64_t refresh_ms = ims_now_ms() +
            ((uint64_t)(IMS_REGISTER_EXPIRES_SECONDS - IMS_REGISTER_REFRESH_MARGIN_SECONDS) * 1000u);

        (void)header_get_uint(udp.payload, udp.payload_len, "Expires:", &expires);
        if (expires <= IMS_REGISTER_REFRESH_MARGIN_SECONDS)
            expires = IMS_REGISTER_EXPIRES_SECONDS;
        refresh_ms = ims_now_ms() +
            ((uint64_t)(expires - IMS_REGISTER_REFRESH_MARGIN_SECONDS) * 1000u);

        pthread_mutex_lock(&svc->lock);
        svc->registered = true;
        svc->register_sent = false;
        svc->register_sent_ms = 0;
        svc->register_attempts = 0;
        svc->register_refresh_ms = refresh_ms;
        pthread_mutex_unlock(&svc->lock);
        LOG_INF(IMS, "IMS SIP REGISTER accepted");
    } else if (udp.payload_len >= 11 && !memcmp(udp.payload, "SIP/2.0 401", 11) &&
               header_has_cseq_method(udp.payload, udp.payload_len, "REGISTER")) {
        struct sip_auth_challenge challenge = {0};

        LOG_INF(IMS, "IMS SIP REGISTER challenged");
        if (parse_www_authenticate(udp.payload, udp.payload_len, &challenge)) {
            pthread_mutex_lock(&svc->lock);
            svc->register_auth = challenge;
            svc->register_auth_valid = true;
            pthread_mutex_unlock(&svc->lock);
        }
        if (challenge.nonce[0] && ims_send_authorized_register(svc, &challenge) == 0) {
            /* Reset the retry timer to the authorized REGISTER's send time so the
             * worker waits for its 200 OK instead of retransmitting a fresh
             * initial REGISTER while this one is still in flight. */
            pthread_mutex_lock(&svc->lock);
            svc->register_sent = true;
            svc->register_sent_ms = ims_now_ms();
            pthread_mutex_unlock(&svc->lock);
            LOG_INF(IMS, "IMS SIP REGISTER authorization sent");
        } else {
            LOG_WRN(IMS, "IMS SIP REGISTER authorization failed");
        }
    }
}

static int ims_send_initial_register(struct ims_service *svc,
                                     const uint8_t local_ip[4],
                                     const uint8_t pcscf_ip[4],
                                     ims_service_tx_ip_cb tx_cb,
                                     void *tx_cb_data)
{
    char sip[1600];
    uint8_t packet[1800];
    char contact_uri[256];
    int sip_len;
    int packet_len;

    if (!tx_cb)
        return -ENODEV;

    if (ims_build_contact_uri(contact_uri, sizeof(contact_uri), svc, local_ip) < 0)
        return -EMSGSIZE;

    sip_len = snprintf(sip, sizeof(sip),
                       "REGISTER sip:%s SIP/2.0\r\n"
                       "Via: SIP/2.0/UDP %u.%u.%u.%u:%u;branch=z9hG4bK-virtlte-1\r\n"
                       "Max-Forwards: 70\r\n"
                       "From: <%s>;tag=virtlte-1\r\n"
                       "To: <%s>\r\n"
                       "Call-ID: virtlte-register-1@%u.%u.%u.%u\r\n"
                       "CSeq: 1 REGISTER\r\n"
                       "Supported: path\r\n"
                       "Contact: <%s>;+g.3gpp.smsip\r\n"
                       "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"\", uri=\"sip:%s\", response=\"\"\r\n"
                       "Expires: 600\r\n"
                       "Content-Length: 0\r\n\r\n",
                       svc->realm,
                       local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                       IMS_SIP_LOCAL_PORT,
                       svc->preferred_impu,
                       svc->preferred_impu,
                       local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                       contact_uri,
                       svc->impi,
                       svc->realm,
                       svc->realm);

    if (sip_len <= 0 || (size_t)sip_len >= sizeof(sip))
        return -EMSGSIZE;

    packet_len = ims_ip_build_udp_ipv4(packet, sizeof(packet),
                                       local_ip, pcscf_ip,
                                       IMS_SIP_LOCAL_PORT,
                                       IMS_SIP_REMOTE_PORT,
                                       (const uint8_t *)sip,
                                       (size_t)sip_len);
    if (packet_len < 0)
        return packet_len;

    return tx_cb(packet, (size_t)packet_len, tx_cb_data);
}

static int ims_send_authorized_register(struct ims_service *svc,
                                        const struct sip_auth_challenge *challenge)
{
    uint8_t res[8];
    uint8_t local_ip[4];
    uint8_t pcscf_ip[4];
    ims_service_tx_ip_cb tx_cb;
    void *tx_cb_data;
    const char *realm;
    const char *qop;
    const char *nc = "00000001";
    char cnonce[17];
    char qop_clause[80];
    char uri[128];
    char response[33];
    char sip[1600];
    char contact_uri[256];
    uint8_t packet[2048];
    uint32_t cseq;
    int sip_len;
    int packet_len;

    if (!svc || !challenge)
        return -EINVAL;
    if (strcasecmp(challenge->algorithm, "AKAv1-MD5") &&
        strcasecmp(challenge->algorithm, "MD5"))
        return -ENOTSUP;
    if (!ims_compute_aka_res(svc, challenge->nonce, res))
        return -EACCES;

    pthread_mutex_lock(&svc->lock);
    if (!svc->pdu_active || !svc->has_pcscf || !svc->tx_cb) {
        pthread_mutex_unlock(&svc->lock);
        return -ENODEV;
    }
    memcpy(local_ip, svc->ipv4, 4);
    memcpy(pcscf_ip, svc->pcscf_ipv4, 4);
    tx_cb = svc->tx_cb;
    tx_cb_data = svc->tx_cb_data;
    cseq = svc->next_sip_cseq++;
    pthread_mutex_unlock(&svc->lock);

    if (ims_build_contact_uri(contact_uri, sizeof(contact_uri), svc, local_ip) < 0)
        return -EMSGSIZE;

    realm = challenge->realm[0] ? challenge->realm : svc->realm;
    qop = challenge->qop[0] ? challenge->qop : NULL;
    snprintf(uri, sizeof(uri), "sip:%s", svc->realm);

    /* Fresh per-request client nonce (anti-replay), from the kernel CSPRNG; the
     * same value is used in the digest computation below and in the header. */
    ims_random_hex(cnonce, sizeof(cnonce));
    if (qop)
        snprintf(qop_clause, sizeof(qop_clause),
                 ", qop=auth, nc=%s, cnonce=\"%s\"", nc, cnonce);
    else
        qop_clause[0] = '\0';

    if (ims_digest_md5_response(response,
                                svc->impi,
                                realm,
                                res,
                                sizeof(res),
                                "REGISTER",
                                uri,
                                challenge->nonce,
                                qop ? nc : NULL,
                                qop ? cnonce : NULL,
                                qop) < 0)
        return -EINVAL;

    sip_len = snprintf(sip, sizeof(sip),
                       "REGISTER sip:%s SIP/2.0\r\n"
                       "Via: SIP/2.0/UDP %u.%u.%u.%u:%u;branch=z9hG4bK-virtlte-auth-%u\r\n"
                       "Max-Forwards: 70\r\n"
                       "From: <%s>;tag=virtlte-1\r\n"
                       "To: <%s>\r\n"
                       "Call-ID: virtlte-register-1@%u.%u.%u.%u\r\n"
                       "CSeq: %u REGISTER\r\n"
                       "Supported: path\r\n"
                       "Contact: <%s>;+g.3gpp.smsip\r\n"
                       "Authorization: Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", response=\"%s\", algorithm=%s%s%s\r\n"
                       "Expires: 600\r\n"
                       "Content-Length: 0\r\n\r\n",
                       svc->realm,
                       local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                       IMS_SIP_LOCAL_PORT, cseq,
                       svc->preferred_impu,
                       svc->preferred_impu,
                       local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                       cseq,
                       contact_uri,
                       svc->impi,
                       realm,
                       challenge->nonce,
                       uri,
                       response,
                       challenge->algorithm[0] ? challenge->algorithm : "AKAv1-MD5",
                       qop_clause,
                       "");
    if (sip_len <= 0 || (size_t)sip_len >= sizeof(sip))
        return -EMSGSIZE;

    packet_len = ims_ip_build_udp_ipv4(packet, sizeof(packet),
                                       local_ip, pcscf_ip,
                                       IMS_SIP_LOCAL_PORT,
                                       IMS_SIP_REMOTE_PORT,
                                       (const uint8_t *)sip,
                                       (size_t)sip_len);
    if (packet_len < 0)
        return packet_len;

    return tx_cb(packet, (size_t)packet_len, tx_cb_data);
}

/*
 * Build a mobile-originated RP-DATA RPDU (3GPP TS 24.011 §7.3.1.1) carrying the
 * SMS-SUBMIT TPDU. SMS over IMS (TS 24.341) puts this RPDU — not the bare TPDU —
 * in the SIP MESSAGE body (Content-Type application/vnd.3gpp.sms).
 *
 * The MBIM SMS PDU is [SCA-len][SCA value][TPDU] (the 27.005 PDU-mode layout:
 * a service-centre address prefix, SCA-len=0 meaning "no SMSC", then the TS
 * 23.040 SMS-SUBMIT TPDU). The SCA must be stripped — only the TPDU goes into
 * RP-User-Data. The SCA becomes RP-Destination Address when present, else the
 * network uses the subscriber's default SMSC:
 *   RP-MTI(0x00) | RP-MR(1) | RP-OA(len=0) | RP-DA(SCA or len=0) | RP-UD(len + TPDU)
 * Returns the RPDU length, or -1 on malformed input / overflow.
 */
/* ims_build_rp_data(): moved to ims_rpdata.c (unit-tested in isolation). */

static int ims_send_sms_message(struct ims_service *svc,
                                const struct ims_sms_item *sms,
                                const uint8_t local_ip[4],
                                const uint8_t pcscf_ip[4],
                                ims_service_tx_ip_cb tx_cb,
                                void *tx_cb_data)
{
    char dst[64];
    char request_uri[200];   /* fits preferred_impu[180] and sip:<dst>@<realm>;user=phone */
    char header[1024];
    uint8_t rpdu[IMS_SMS_PDU_MAX + 16];
    uint8_t sip[1600];
    uint8_t packet[2048];
    int rpdu_len;
    int header_len;
    int packet_len;
    uint32_t cseq;

    if (!tx_cb || !sms || sms->pdu_len > IMS_SMS_PDU_MAX)
        return -EINVAL;

    /* SIP body = RP-DATA RPDU wrapping the TPDU, not the raw MBIM PDU. */
    rpdu_len = ims_build_rp_data(sms->pdu, sms->pdu_len,
                                 (uint8_t)sms->reference, rpdu, sizeof(rpdu));
    if (rpdu_len <= 0) {
        LOG_WRN(IMS, "IMS SMS RP-DATA build failed len=%zu", sms->pdu_len);
        return -EINVAL;
    }

    if (ims_sms_extract_destination(sms->pdu, sms->pdu_len, dst, sizeof(dst)))
        snprintf(request_uri, sizeof(request_uri), "sip:%s@%s;user=phone", dst, svc->realm);
    else
        snprintf(request_uri, sizeof(request_uri), "%s", svc->preferred_impu);

    pthread_mutex_lock(&svc->lock);
    cseq = svc->next_sip_cseq++;
    pthread_mutex_unlock(&svc->lock);

    header_len = snprintf(header, sizeof(header),
                          "MESSAGE %s SIP/2.0\r\n"
                          "Via: SIP/2.0/UDP %u.%u.%u.%u:%u;branch=z9hG4bK-virtlte-sms-%u\r\n"
                          "Max-Forwards: 70\r\n"
                          "From: <%s>;tag=virtlte-sms\r\n"
                          "To: <%s>\r\n"
                          "Call-ID: virtlte-sms-%u@%u.%u.%u.%u\r\n"
                          "CSeq: %u MESSAGE\r\n"
                          "Content-Type: application/vnd.3gpp.sms\r\n"
                          "Content-Length: %d\r\n\r\n",
                          request_uri,
                          local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                          IMS_SIP_LOCAL_PORT, sms->reference,
                          svc->preferred_impu,
                          request_uri,
                          sms->reference,
                          local_ip[0], local_ip[1], local_ip[2], local_ip[3],
                          cseq,
                          rpdu_len);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header)) {
        LOG_WRN(IMS, "IMS SMS header build failed (len=%d)", header_len);
        return -EMSGSIZE;
    }
    if ((size_t)header_len + (size_t)rpdu_len > sizeof(sip)) {
        LOG_WRN(IMS, "IMS SMS too large (hdr=%d rpdu=%d)", header_len, rpdu_len);
        return -EMSGSIZE;
    }

    memcpy(sip, header, (size_t)header_len);
    memcpy(sip + header_len, rpdu, (size_t)rpdu_len);

    packet_len = ims_ip_build_udp_ipv4(packet, sizeof(packet),
                                       local_ip, pcscf_ip,
                                       IMS_SIP_LOCAL_PORT,
                                       IMS_SIP_REMOTE_PORT,
                                       sip,
                                       (size_t)header_len + (size_t)rpdu_len);
    if (packet_len < 0) {
        LOG_WRN(IMS, "IMS SMS IP/UDP build failed rc=%d sip_len=%d",
                packet_len, header_len + rpdu_len);
        return packet_len;
    }

    {
        int rc = tx_cb(packet, (size_t)packet_len, tx_cb_data);
        if (rc != 0)
            LOG_WRN(IMS, "IMS SMS tx_cb failed rc=%d (uplink inject)", rc);
        return rc;
    }
}

static void *ims_worker(void *arg)
{
    struct ims_service *svc = arg;

    LOG_INF(IMS, "IMS service worker started");

    for (;;) {
        struct ims_sms_item sms_item;
        struct ims_ip_item ip_item;
        bool do_register;
        bool do_refresh;
        bool pdu_ready;
        bool registered;
        uint64_t now_ms;
        struct sip_auth_challenge refresh_auth;
        uint8_t local_ip[4];
        uint8_t pcscf_ip[4];
        ims_service_tx_ip_cb tx_cb;
        void *tx_cb_data;
        bool have_sms;
        bool have_ip;

        pthread_mutex_lock(&svc->lock);
        now_ms = ims_now_ms();
        while (svc->running && sms_queue_empty(svc) && ip_queue_empty(svc) &&
               !register_needed_locked(svc) &&
               !register_refresh_needed_locked(svc, now_ms) &&
               !register_retry_needed_locked(svc, now_ms)) {
            uint64_t deadline_ms;

            if (next_register_refresh_deadline_locked(svc, &deadline_ms)) {
                struct timespec deadline;

                realtime_from_monotonic_deadline(deadline_ms, &deadline);
                pthread_cond_timedwait(&svc->cond, &svc->lock, &deadline);
            } else {
                pthread_cond_wait(&svc->cond, &svc->lock);
            }
            now_ms = ims_now_ms();
        }
        if (!svc->running) {
            pthread_mutex_unlock(&svc->lock);
            break;
        }
        /* Unanswered initial REGISTER timed out: rearm for a fresh attempt. */
        if (register_retry_needed_locked(svc, now_ms)) {
            svc->register_sent = false;
            svc->register_auth_valid = false;
            LOG_WRN(IMS, "IMS SIP REGISTER no response, retransmitting (attempt %d/%d)",
                    svc->register_attempts + 1, IMS_REGISTER_MAX_ATTEMPTS);
        }
        do_register = register_needed_locked(svc);
        do_refresh = register_refresh_needed_locked(svc, now_ms);
        if (do_refresh) {
            refresh_auth = svc->register_auth;
            svc->register_refresh_ms = 0;
        } else {
            memset(&refresh_auth, 0, sizeof(refresh_auth));
        }
        if (do_register) {
            svc->register_sent = true;
            svc->register_sent_ms = now_ms;
            svc->register_attempts++;
            memcpy(local_ip, svc->ipv4, 4);
            memcpy(pcscf_ip, svc->pcscf_ipv4, 4);
            tx_cb = svc->tx_cb;
            tx_cb_data = svc->tx_cb_data;
        } else {
            memset(local_ip, 0, sizeof(local_ip));
            memset(pcscf_ip, 0, sizeof(pcscf_ip));
            tx_cb = NULL;
            tx_cb_data = NULL;
        }
        pdu_ready = svc->pdu_active && svc->has_pcscf;
        registered = svc->registered;
        if (!do_register && pdu_ready) {
            memcpy(local_ip, svc->ipv4, 4);
            memcpy(pcscf_ip, svc->pcscf_ipv4, 4);
            tx_cb = svc->tx_cb;
            tx_cb_data = svc->tx_cb_data;
        }
        have_sms = sms_queue_pop_locked(svc, &sms_item);
        have_ip = ip_queue_pop_locked(svc, &ip_item);
        pthread_mutex_unlock(&svc->lock);

        if (do_register) {
            if (ims_send_initial_register(svc, local_ip, pcscf_ip, tx_cb, tx_cb_data) == 0)
                LOG_INF(IMS, "IMS SIP REGISTER sent");
            else
                LOG_WRN(IMS, "IMS SIP REGISTER send failed");
        }

        if (do_refresh) {
            int refresh_rc;

            if (refresh_auth.nonce[0])
                refresh_rc = ims_send_authorized_register(svc, &refresh_auth);
            else
                refresh_rc = ims_send_initial_register(svc, local_ip, pcscf_ip, tx_cb, tx_cb_data);
            if (refresh_rc == 0)
                LOG_INF(IMS, "IMS SIP REGISTER refresh sent");
            else
                LOG_WRN(IMS, "IMS SIP REGISTER refresh failed");
        }

        if (have_ip) {
            LOG_TRC(IMS, "IMS worker RX IP psi=%d len=%zu", ip_item.psi, ip_item.packet_len);
            ims_handle_rx_ip(svc, &ip_item);
        }

        if (have_sms) {
            if (registered && pdu_ready &&
                ims_send_sms_message(svc, &sms_item, local_ip, pcscf_ip,
                                     tx_cb, tx_cb_data) == 0) {
                LOG_INF(IMS, "IMS SMS MESSAGE sent ref=%u len=%zu",
                        sms_item.reference, sms_item.pdu_len);
            } else {
                LOG_WRN(IMS, "IMS SMS MESSAGE send failed ref=%u registered=%s pdu_ready=%s",
                        sms_item.reference,
                        registered ? "yes" : "no",
                        pdu_ready ? "yes" : "no");
            }
        }
    }

    LOG_INF(IMS, "IMS service worker stopped");
    return NULL;
}

int ims_service_init(struct ims_service **out,
                     const struct ue_instance_config *cfg)
{
    struct ims_service *svc;

    if (!out || !cfg)
        return -EINVAL;

    *out = NULL;
    svc = calloc(1, sizeof(*svc));
    if (!svc)
        return -ENOMEM;

    svc->enabled = cfg->ims.enabled;
    svc->sms_enabled = cfg->sms.enabled;
    svc->next_sms_reference = 1;
    svc->next_sip_cseq = 2;
    ims_build_identity(svc, cfg);
    pthread_mutex_init(&svc->lock, NULL);
    pthread_cond_init(&svc->cond, NULL);

    if (svc->enabled) {
        int rc;

        svc->running = true;
        rc = pthread_create(&svc->thread, NULL, ims_worker, svc);
        if (rc != 0) {
            pthread_cond_destroy(&svc->cond);
            pthread_mutex_destroy(&svc->lock);
            free(svc);
            return -rc;
        }
        svc->thread_started = true;
    }

    LOG_INF(IMS, "IMS service init enabled=%s sms_enabled=%s",
            svc->enabled ? "yes" : "no",
            svc->sms_enabled ? "yes" : "no");
    if (svc->enabled)
        LOG_INF(IMS, "IMS identity realm=%s impi=%s preferred_impu=%s",
                svc->realm, svc->impi, svc->preferred_impu);

    *out = svc;
    return 0;
}

void ims_service_destroy(struct ims_service *svc)
{
    if (!svc)
        return;

    pthread_mutex_lock(&svc->lock);
    svc->running = false;
    pthread_cond_signal(&svc->cond);
    pthread_mutex_unlock(&svc->lock);

    if (svc->thread_started)
        pthread_join(svc->thread, NULL);

    pthread_cond_destroy(&svc->cond);
    pthread_mutex_destroy(&svc->lock);
    free(svc);
}

bool ims_service_enabled(const struct ims_service *svc)
{
    return svc && svc->enabled;
}

bool ims_service_registered(struct ims_service *svc)
{
    bool registered;

    if (!svc)
        return false;
    pthread_mutex_lock(&svc->lock);
    registered = svc->registered;
    pthread_mutex_unlock(&svc->lock);
    return registered;
}

void ims_service_set_pdu_active(struct ims_service *svc,
                                bool active,
                                const uint8_t ipv4[4],
                                bool has_pcscf,
                                const uint8_t pcscf_ipv4[4])
{
    bool changed;

    if (!svc)
        return;

    pthread_mutex_lock(&svc->lock);
    changed = svc->pdu_active != active;
    if (changed || !active) {
        svc->register_sent = false;
        svc->register_sent_ms = 0;
        svc->register_attempts = 0;
    }
    if (!active) {
        svc->registered = false;
        svc->register_auth_valid = false;
        svc->register_refresh_ms = 0;
        memset(&svc->register_auth, 0, sizeof(svc->register_auth));
        /* Drop any queued SMS / inbound IP from the torn-down IMS session. */
        svc->sms_head = svc->sms_tail = 0;
        svc->ip_head = svc->ip_tail = 0;
    }
    svc->pdu_active = active;
    if (active && ipv4)
        memcpy(svc->ipv4, ipv4, 4);
    svc->has_pcscf = active && has_pcscf;
    if (active && has_pcscf && pcscf_ipv4)
        memcpy(svc->pcscf_ipv4, pcscf_ipv4, 4);
    pthread_cond_signal(&svc->cond);
    pthread_mutex_unlock(&svc->lock);

    if (changed)
        LOG_INF(IMS, "IMS PDU state active=%s pcscf=%s", active ? "yes" : "no",
                has_pcscf ? "yes" : "no");
}

void ims_service_set_tx_callback(struct ims_service *svc,
                                 ims_service_tx_ip_cb cb,
                                 void *user_data)
{
    if (!svc)
        return;
    pthread_mutex_lock(&svc->lock);
    svc->tx_cb = cb;
    svc->tx_cb_data = user_data;
    pthread_mutex_unlock(&svc->lock);
}

void ims_service_set_sms_downlink_callback(struct ims_service *svc,
                                           ims_service_sms_downlink_cb cb,
                                           void *user_data)
{
    if (!svc)
        return;
    pthread_mutex_lock(&svc->lock);
    svc->sms_dl_cb = cb;
    svc->sms_dl_cb_data = user_data;
    pthread_mutex_unlock(&svc->lock);
}

int ims_service_submit_sms(struct ims_service *svc,
                           const uint8_t *pdu,
                           size_t pdu_len,
                           uint32_t *reference)
{
    uint32_t ref;

    if (!svc || !pdu || pdu_len == 0)
        return -EINVAL;
    if (!svc->enabled || !svc->sms_enabled)
        return -ENODEV;
    if (pdu_len > IMS_SMS_PDU_MAX)
        return -EMSGSIZE;

    pthread_mutex_lock(&svc->lock);
    if (!svc->registered) {
        pthread_mutex_unlock(&svc->lock);
        return -EAGAIN;
    }
    if (sms_queue_full(svc)) {
        pthread_mutex_unlock(&svc->lock);
        return -ENOSPC;
    }

    ref = svc->next_sms_reference++;
    svc->sms_queue[svc->sms_tail].reference = ref;
    memcpy(svc->sms_queue[svc->sms_tail].pdu, pdu, pdu_len);
    svc->sms_queue[svc->sms_tail].pdu_len = pdu_len;
    svc->sms_tail = (svc->sms_tail + 1) % IMS_SMS_QUEUE_SIZE;
    pthread_cond_signal(&svc->cond);
    pthread_mutex_unlock(&svc->lock);

    if (reference)
        *reference = ref;
    return 0;
}

int ims_service_receive_ip(struct ims_service *svc,
                           int psi,
                           const uint8_t *packet,
                           size_t packet_len)
{
    if (!svc || !packet || packet_len == 0)
        return -1;
    if (!svc->enabled)
        return -1;
    if (packet_len > IMS_IP_PACKET_MAX)
        return -1;

    pthread_mutex_lock(&svc->lock);
    if (ip_queue_full(svc)) {
        pthread_mutex_unlock(&svc->lock);
        return -1;
    }
    svc->ip_queue[svc->ip_tail].psi = psi;
    memcpy(svc->ip_queue[svc->ip_tail].packet, packet, packet_len);
    svc->ip_queue[svc->ip_tail].packet_len = packet_len;
    svc->ip_tail = (svc->ip_tail + 1) % IMS_IP_QUEUE_SIZE;
    pthread_cond_signal(&svc->cond);
    pthread_mutex_unlock(&svc->lock);
    return 0;
}
