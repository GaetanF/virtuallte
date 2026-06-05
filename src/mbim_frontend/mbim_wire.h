#ifndef MBIM_WIRE_H
#define MBIM_WIRE_H

/*
 * mbim_wire - typed wire structs (binary-layout reference) + a small
 * builder/serialiser and debug dumpers for MBIM InformationBuffers.
 *
 * THE STRUCTS BELOW ARE COPIED VERBATIM FROM umbim (OpenWrt), so they can be
 * diffed 1:1 against the reference layout:
 *
 *   umbim/mbim-type.h                       -> struct mbim_string
 *   umbim/data/mbim-service-basic-connect.h -> struct mbim_basic_connect_*
 *
 * Only the response-side structs of the CIDs we actually emit are kept (the
 * umbim "_r" suffix is dropped since no other variant is present), plus the
 * shared element sub-structs they reference. The notification (_n), set (_s)
 * and query (_q) variants are intentionally omitted.
 *
 * Field names and the "enum ..." annotation comments are kept identical to
 * umbim on purpose; do not "tidy" them - they are the contract.
 *
 *
 * OFFSET BASE CONVENTIONS (critical - matches umbim mbim_get_string()):
 *
 *   - Top-level CID structs (e.g. subscriber_ready_status_r): the offset in
 *     each `struct mbim_string` is relative to the START OF THE
 *     InformationBuffer. umbim resolves them with
 *         mbim_get_string(&state->subscriberid, information_buffer);
 *
 *   - ref-struct-array elements (e.g. an mbimprovisionedcontextelement inside
 *     PROVISIONED_CONTEXTS): the `struct mbim_string` offsets INSIDE the
 *     element are relative to the START OF THAT ELEMENT, not the
 *     InformationBuffer. (Same base as Wireshark's mbim_dissect_context().)
 *
 * The builder models both via builder->frame_base: a stored offset is computed
 * as (absolute_position - frame_base). frame_base == 0 -> InformationBuffer
 * relative; set frame_base to the element start -> element relative.
 */

#include <stdbool.h>
#include <stdint.h>

#include "../common/log.h"

/* ========================================================================== */
/* Wire structs - verbatim from umbim (do not rename fields)                  */
/* ========================================================================== */

/* umbim/mbim-type.h */
struct mbim_string {
    uint32_t offset;
    uint32_t length;
} __attribute__((packed));

/* ID 1: Device Caps */
struct mbim_basic_connect_device_caps {
    /* enum MbimDeviceType */
    uint32_t devicetype;
    /* enum MbimCellularClass */
    uint32_t cellularclass;
    /* enum MbimVoiceClass */
    uint32_t voiceclass;
    /* enum MbimSimClass */
    uint32_t simclass;
    /* enum MbimDataClass */
    uint32_t dataclass;
    /* enum MbimSmsCaps */
    uint32_t smscaps;
    /* enum MbimCtrlCaps */
    uint32_t controlcaps;
    uint32_t maxsessions;
    struct mbim_string customdataclass;
    struct mbim_string deviceid;
    struct mbim_string firmwareinfo;
    struct mbim_string hardwareinfo;
} __attribute__((packed));

/* ID 2: Subscriber Ready Status */
struct mbim_basic_connect_subscriber_ready_status {
    /* enum MbimSubscriberReadyState */
    uint32_t readystate;
    struct mbim_string subscriberid;
    struct mbim_string simiccid;
    /* enum MbimReadyInfoFlag */
    uint32_t readyinfo;
    uint32_t telephonenumberscount;
    /* array type: string-array */
    uint32_t telephonenumbers;
} __attribute__((packed));

/* ID 3: Radio State */
struct mbim_basic_connect_radio_state {
    /* enum MbimRadioSwitchState */
    uint32_t hwradiostate;
    /* enum MbimRadioSwitchState */
    uint32_t swradiostate;
} __attribute__((packed));

/* ID 9: Register State */
struct mbim_basic_connect_register_state {
    /* enum MbimNwError */
    uint32_t nwerror;
    /* enum MbimRegisterState */
    uint32_t registerstate;
    /* enum MbimRegisterMode */
    uint32_t registermode;
    /* enum MbimDataClass */
    uint32_t availabledataclasses;
    /* enum MbimCellularClass */
    uint32_t currentcellularclass;
    struct mbim_string providerid;
    struct mbim_string providername;
    struct mbim_string roamingtext;
    /* enum MbimRegistrationFlag */
    uint32_t registrationflag;
} __attribute__((packed));

/* ID 10: Packet Service */
struct mbim_basic_connect_packet_service {
    uint32_t nwerror;
    /* enum MbimPacketServiceState */
    uint32_t packetservicestate;
    /* enum MbimDataClass */
    uint32_t highestavailabledataclass;
    uint64_t uplinkspeed;
    uint64_t downlinkspeed;
} __attribute__((packed));

/* ID 11: Signal State */
struct mbim_basic_connect_signal_state {
    uint32_t rssi;
    uint32_t errorrate;
    uint32_t signalstrengthinterval;
    uint32_t rssithreshold;
    uint32_t errorratethreshold;
} __attribute__((packed));

/* ID 12: Connect */
struct mbim_basic_connect_connect {
    uint32_t sessionid;
    /* enum MbimActivationState */
    uint32_t activationstate;
    /* enum MbimVoiceCallState */
    uint32_t voicecallstate;
    /* enum MbimContextIpType */
    uint32_t iptype;
    uint8_t contexttype[16];
    uint32_t nwerror;
} __attribute__((packed));

/*
 * shared: one provisioned-context entry (ref-struct-array element).
 *
 * NOTE: this is the 60-byte layout that carries the trailing `providerid`
 * (same fields as umbim's mbim_basic_connect_provisioned_contexts_s), NOT the
 * 52-byte umbim `mbimprovisionedcontextelement`. RouterOS expects the
 * providerid field; omitting it left each element 8 bytes short. With
 * providerid present, accessstring.offset is 60 (element-relative) and
 * providerid is {0,0} when no provider is bound.
 */
struct mbimprovisionedcontextelement {
    uint32_t contextid;
    uint8_t contexttype[16];
    struct mbim_string accessstring;
    struct mbim_string username;
    struct mbim_string password;
    /* enum MbimCompression */
    uint32_t compression;
    /* enum MbimAuthProtocol */
    uint32_t authprotocol;
    struct mbim_string providerid;
} __attribute__((packed));

/* ID 13: Provisioned Contexts */
struct mbim_basic_connect_provisioned_contexts {
    uint32_t provisionedcontextscount;
    /* array type: ref-struct-array */
    uint32_t provisionedcontexts;
} __attribute__((packed));

/* shared: IP config address elements */
struct mbimipv4element {
    uint32_t onlinkprefixlength;
    uint8_t ipv4address[4];
} __attribute__((packed));

struct mbimipv6element {
    uint32_t onlinkprefixlength;
    uint8_t ipv6address[16];
} __attribute__((packed));

/* ID 15: IP Configuration */
struct mbim_basic_connect_ip_configuration {
    uint32_t sessionid;
    /* enum MbimIPConfigurationAvailableFlag */
    uint32_t ipv4configurationavailable;
    /* enum MbimIPConfigurationAvailableFlag */
    uint32_t ipv6configurationavailable;
    uint32_t ipv4addresscount;
    /* struct mbimipv4element */
    uint32_t ipv4address;
    uint32_t ipv6addresscount;
    /* struct mbimipv6element */
    uint32_t ipv6address;
    /* array type: ref-ipv4 */
    uint32_t ipv4gateway;
    /* array type: ref-ipv6 */
    uint32_t ipv6gateway;
    uint32_t ipv4dnsservercount;
    /* array type: ipv4-array */
    uint32_t ipv4dnsserver;
    uint32_t ipv6dnsservercount;
    /* array type: ipv6-array */
    uint32_t ipv6dnsserver;
    uint32_t ipv4mtu;
    uint32_t ipv6mtu;
} __attribute__((packed));

/* shared: device service element (ref-struct-array element) */
struct mbimdeviceserviceelement {
    uint8_t deviceserviceid[16];
    uint32_t dsspayload;
    uint32_t maxdssinstances;
    uint32_t cidscount;
    /* array type: guint32-array */
    uint32_t cids;
} __attribute__((packed));

/* ID 16: Device Services */
struct mbim_basic_connect_device_services {
    uint32_t deviceservicescount;
    uint32_t maxdsssessions;
    /* array type: ref-struct-array */
    uint32_t deviceservices;
} __attribute__((packed));

/* -------------------------------------------------------------------------- */
/* Other shared data sub-structs (verbatim from umbim), kept for completeness  */
/* so future handlers reuse the typed layout instead of raw offsets.           */
/* -------------------------------------------------------------------------- */

/* PIN descriptor (umbim mbimpindesc) */
struct mbimpindesc {
    /* enum MbimPinMode */
    uint32_t pinmode;
    /* enum MbimPinFormat */
    uint32_t pinformat;
    uint32_t pinlengthmin;
    uint32_t pinlengthmax;
} __attribute__((packed));

/* Network provider (umbim mbimprovider) */
struct mbimprovider {
    struct mbim_string providerid;
    /* enum MbimProviderState */
    uint32_t providerstate;
    struct mbim_string providername;
    /* enum MbimCellularClass */
    uint32_t cellularclass;
    uint32_t rssi;
    uint32_t errorrate;
} __attribute__((packed));

/* Device-service-subscribe event entry (umbim mbimevententry) */
struct mbimevententry {
    uint8_t deviceserviceid[16];
    uint32_t cidscount;
    /* array type: guint32-array */
    uint32_t cids;
} __attribute__((packed));

/* IP packet filter (umbim mbimpacketfilter) */
struct mbimpacketfilter {
    uint32_t filtersize;
    /* array type: ref-byte-array */
    uint32_t packetfilter;
    /* array type: ref-byte-array */
    uint32_t packetmask;
} __attribute__((packed));

/* ========================================================================== */
/* MS Basic Connect Extensions service (UUID_BASIC_CONNECT_EXTENSIONS)        */
/*                                                                            */
/* umbim does NOT cover this service. Reference: libmbim                      */
/* mbim-service-ms-basic-connect-extensions.json (MbimLteAttachConfiguration, */
/* "LTE Attach Info"). Field names/order kept identical to that reference.    */
/* ========================================================================== */

/*
 * CID 1 MS Provisioned Contexts V2 - one context element (MBIM_MS_CONTEXT_V2).
 * Reference: Microsoft windows-driver-docs mb-provisioned-context-operations.
 * 72B fixed; accessstring/username/password offsets are ELEMENT-relative.
 */
struct mbim_ms_context_v2 {
    uint32_t contextid;
    uint8_t  contexttype[16];
    /* enum MbimContextIpType */
    uint32_t iptype;
    /* enum MbimMsContextEnable: Disabled=0, Enabled=1 */
    uint32_t enable;
    /* enum MbimMsContextRoamingControl: HomeOnly=0..AllowAll=6 */
    uint32_t roaming;
    /* enum MbimMsContextMediaType: CellularOnly=0, WifiOnly=1, All=2 */
    uint32_t mediatype;
    /* enum MbimMsContextSource: Admin=0, User=1, Operator=2, Modem=3, Device=4 */
    uint32_t source;
    struct mbim_string accessstring;
    struct mbim_string username;
    struct mbim_string password;
    /* enum MbimCompression */
    uint32_t compression;
    /* enum MbimAuthProtocol */
    uint32_t authprotocol;
} __attribute__((packed));

/*
 * CID 1 MS Provisioned Contexts V2 query response
 * (MBIM_MS_PROVISIONED_CONTEXTS_INFO_V2). 8B fixed: ElementCount + a
 * ref-struct-array of mbim_ms_context_v2.
 */
struct mbim_ms_provisioned_contexts_info_v2 {
    uint32_t elementcount;
    /* array type: ref-struct-array */
    uint32_t provisionedcontexts;
} __attribute__((packed));

/*
 * CID 3 LTE Attach Configuration - one configuration entry
 * (libmbim MbimLteAttachConfiguration), used as a ref-struct-array element.
 * 44B fixed. The accessstring/username/password offsets are ELEMENT-relative.
 */
struct mbim_ms_lte_attach_configuration {
    /* enum MbimContextIpType */
    uint32_t iptype;
    /* enum MbimLteAttachContextRoamingControl: Home=0, Partner=1, NonPartner=2 */
    uint32_t roaming;
    /* enum MbimContextSource */
    uint32_t source;
    struct mbim_string accessstring;
    struct mbim_string username;
    struct mbim_string password;
    /* enum MbimCompression */
    uint32_t compression;
    /* enum MbimAuthProtocol */
    uint32_t authprotocol;
} __attribute__((packed));

/*
 * CID 3 LTE Attach Configuration query response / notification. 8B fixed,
 * then ConfigurationsRefList (OL_PAIR array) + DataBuffer with the entries.
 */
struct mbim_ms_lte_attach_configuration_info {
    uint32_t configurationcount;
    /* array type: ref-struct-array */
    uint32_t configurations;
} __attribute__((packed));

/*
 * CID 4 LTE Attach Status (libmbim "LTE Attach Info"). 40B fixed, then the
 * DataBuffer; accessstring/username/password offsets are relative to the
 * InformationBuffer.
 */
struct mbim_ms_lte_attach_status {
    /* enum MbimMsLteAttachState: Detached=0, Attached=1 */
    uint32_t lteattachstate;
    /* enum MbimContextIpType */
    uint32_t iptype;
    struct mbim_string accessstring;
    struct mbim_string username;
    struct mbim_string password;
    /* enum MbimCompression */
    uint32_t compression;
    /* enum MbimAuthProtocol */
    uint32_t authprotocol;
} __attribute__((packed));

/* ========================================================================== */
/* SMS service (UUID_SMS) - reference: umbim/data/mbim-service-sms.h          */
/* ========================================================================== */

/* CID 1: SMS Configuration query response. 24B fixed + scaddress string. */
struct mbim_sms_configuration {
    /* enum MbimSmsStorageState: NotInitialized=0, Initialized=1 */
    uint32_t smsstoragestate;
    /* enum MbimSmsFormat: Pdu=0, Cdma=1 */
    uint32_t format;
    uint32_t maxmessages;
    uint32_t cdmashortmessagesize;
    struct mbim_string scaddress;
} __attribute__((packed));

/* CID 2: SMS Read query response. 16B fixed + ref-struct-arrays. */
struct mbim_sms_read {
    /* enum MbimSmsFormat */
    uint32_t format;
    uint32_t messagescount;
    /* array type: ref-struct-array */
    uint32_t pdumessages;
    /* array type: ref-struct-array */
    uint32_t cdmamessages;
} __attribute__((packed));

/* One PDU record inside MBIM_SMS_READ_INFO pdumessages ref-struct-array. */
struct mbim_sms_pdu_read_record {
    uint32_t messageindex;
    uint32_t messagestatus;
    struct mbim_string pdudata;
} __attribute__((packed));

/* CID 3: SMS Send response. */
struct mbim_sms_send {
    uint32_t messagereference;
} __attribute__((packed));

/* CID 5: SMS Message Store Status response. */
struct mbim_sms_message_store_status {
    /* enum MbimSmsStatusFlag */
    uint32_t flag;
    uint32_t messageindex;
} __attribute__((packed));

/* ========================================================================== */
/* Builder / serialiser                                                       */
/* ========================================================================== */

struct mbim_wire_builder {
    uint8_t *buf;        /* start of the InformationBuffer (== &resp[48]) */
    uint32_t cap;        /* bytes available in buf */
    uint32_t len;        /* high-water mark, relative to buf start */
    uint32_t frame_base; /* mbim_string offsets are computed relative to this */
    bool     overflow;   /* set once any reserve exceeded cap */
};

static inline uint32_t mbim_align4(uint32_t v) { return (v + 3u) & ~3u; }
static inline uint32_t mbim_align8(uint32_t v) { return (v + 7u) & ~7u; }

void mbim_wire_init(struct mbim_wire_builder *b, uint8_t *info_buffer, uint32_t cap);

/* Reserve n zero-filled bytes at the current end; return their buf-relative
 * offset. On overflow, sets b->overflow and returns the clamped offset. */
uint32_t mbim_wire_reserve(struct mbim_wire_builder *b, uint32_t n);

/* Append an ASCII string as UTF-16LE into the DataBuffer (padded to 4 bytes).
 * Fills *out with { offset relative to b->frame_base, length in bytes }.
 * An empty string yields { 0, 0 } (MBIM convention). Returns false on
 * overflow. */
bool mbim_wire_append_string(struct mbim_wire_builder *b, const char *ascii,
                             struct mbim_string *out);

/* Write a struct mbim_string field at *dst (host-order in -> LE on wire). */
void mbim_wire_put_string(struct mbim_string *dst, struct mbim_string v);

/* Low-level: write ASCII as UTF-16LE at dst, return bytes written (2*len). */
uint32_t mbim_wire_write_utf16le(uint8_t *dst, const char *src);

static inline uint32_t mbim_wire_len(const struct mbim_wire_builder *b)
{
    return b->len;
}

/* Validate the built payload and log a one-line summary. Returns false on
 * overflow. Logs an error if len > cap. */
bool mbim_wire_finalize(const struct mbim_wire_builder *b, const char *cid_name);

/* ========================================================================== */
/* Debug helpers                                                              */
/* ========================================================================== */

/* Hexdump `len` bytes of `buf` to the log at LOG_DBG / MBIM. */
void mbim_wire_hexdump(const char *label, const uint8_t *buf, uint32_t len);

/* One-line JSON of the SUBSCRIBER_READY_STATUS logical model. */
void mbim_dump_subscriber_ready_model(uint32_t readystate, const char *imsi,
                                      const char *iccid, uint32_t readyinfo,
                                      uint32_t telcount);

/* One-line JSON of the SUBSCRIBER_READY_STATUS wire layout. */
void mbim_dump_subscriber_ready_wire(const struct mbim_basic_connect_subscriber_ready_status *s,
                                     uint32_t info_len, uint32_t total_msg_len);

/* One-line JSON of the PROVISIONED_CONTEXTS logical model. */
void mbim_dump_provisioned_model(uint32_t count, uint32_t contextid,
                                 const char *contexttype, const char *apn);

/* One-line JSON of the PROVISIONED_CONTEXTS wire layout. */
void mbim_dump_provisioned_wire(uint32_t count, uint32_t elem_off,
                                uint32_t elem_size,
                                const struct mbimprovisionedcontextelement *el,
                                uint32_t info_len, uint32_t total_msg_len);

#endif
