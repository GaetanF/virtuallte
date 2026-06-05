#ifndef MBIM_PROTOCOL_H
#define MBIM_PROTOCOL_H

#include <stdint.h>

#define MBIM_OPEN_MSG 0x00000001
#define MBIM_CLOSE_MSG 0x00000002
#define MBIM_OPEN_DONE 0x80000001
#define MBIM_CLOSE_DONE 0x80000002
#define MBIM_COMMAND_MSG 0x00000003
#define MBIM_COMMAND_DONE 0x80000003
#define MBIM_INDICATE_STATUS_MSG 0x80000007
#define MBIM_STATUS_SUCCESS 0x00000000

#define MBIM_CID_DEVICE_CAPS                   1
#define MBIM_CID_SUBSCRIBER_READY_STATUS       2
#define MBIM_CID_RADIO_STATE                   3
#define MBIM_CID_REGISTER_STATE                9
#define MBIM_CID_PACKET_SERVICE                10
#define MBIM_CID_SIGNAL_STATE                  11
#define MBIM_CID_CONNECT                       12
#define MBIM_CID_PROVISIONED_CONTEXTS          13
#define MBIM_CID_IP_CONFIGURATION              15
#define MBIM_CID_DEVICE_SERVICES               16
#define MBIM_CID_DEVICE_SERVICE_SUBSCRIBE_LIST 19

#define MBIM_EXT_CID_PROVISIONED_CONTEXT_V2    1
/* 2 = NETWORK_BLACKLIST (not implemented) */
#define MBIM_EXT_CID_LTE_ATTACH_CONFIG         3
#define MBIM_EXT_CID_LTE_ATTACH_STATUS         4

/* SMS service CIDs (UUID_SMS) */
#define MBIM_CID_SMS_CONFIGURATION             1
#define MBIM_CID_SMS_READ                      2
#define MBIM_CID_SMS_SEND                      3
#define MBIM_CID_SMS_DELETE                    4
#define MBIM_CID_SMS_MESSAGE_STORE_STATUS      5

/* MBIM_DEVICE_CAPS_INFO SmsCaps bitfield (MbimSmsCapsFlag). */
#define MBIM_SMS_CAPS_PDU_RECEIVE              0x00000001u
#define MBIM_SMS_CAPS_PDU_SEND                 0x00000002u

/* MBIM_SMS_STATUS_INFO Flags (MbimSmsStatusFlag) — bit0=store full, bit1=new. */
#define MBIM_SMS_STATUS_FLAG_NONE              0x00000000u
#define MBIM_SMS_STATUS_FLAG_MESSAGE_STORE_FULL 0x00000001u
#define MBIM_SMS_STATUS_FLAG_NEW_MESSAGE       0x00000002u

/* MBIM_SMS_READ_REQ Flag (MbimSmsFlag). */
#define MBIM_SMS_FLAG_ALL                      0x00000000u
#define MBIM_SMS_FLAG_INDEX                    0x00000001u
#define MBIM_SMS_FLAG_NEW                      0x00000002u

extern const uint8_t UUID_BASIC_CONNECT[16];
extern const uint8_t UUID_EXT_QMUX[16];
extern const uint8_t UUID_BASIC_CONNECT_EXTENSIONS[16];
extern const uint8_t UUID_SMS[16];

#endif
