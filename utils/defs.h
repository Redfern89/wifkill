#ifndef DOT11_UTILS_H
#define DOT11_UTILS_H

#include <stdio.h>
#include <stdint.h>

#define MAC_ADDR_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ADDR_LEN 6

/*
    IEEE 802.11-2016
    9.2 MAC frame formats
      ╰─> 9.2.4.1.3 Type and Subtype subfields
*/

/* Management Frames (Type 00 - Management) */
#define IEEE80211_FC_ASSOC_REQ              0x00  /* Association Request */
#define IEEE80211_FC_ASSOC_RESP             0x10  /* Association Response */
#define IEEE80211_FC_REASSOC_REQ            0x20  /* Reassociation Request */
#define IEEE80211_FC_REASSOC_RESP           0x30  /* Reassociation Response */
#define IEEE80211_FC_PROBE_REQ              0x40  /* Probe Request */
#define IEEE80211_FC_PROBE_RESP             0x50  /* Probe Response */
#define IEEE80211_FC_TIMING_ADV             0x60  /* Timing Advertisement */
#define IEEE80211_FC_BEACON                 0x80  /* Beacon */
#define IEEE80211_FC_ATIM                   0x90  /* ATIM */
#define IEEE80211_FC_DISASSOC               0xA0  /* Disassociation */
#define IEEE80211_FC_AUTH                   0xB0  /* Authentication */
#define IEEE80211_FC_DEAUTH                 0xC0  /* Deauthentication */
#define IEEE80211_FC_ACTION                 0xD0  /* Action */
#define IEEE80211_FC_ACTION_NO_ACK          0xE0  /* Action No Ack */


/* Control Frames (Type 01 - Control) */
#define IEEE80211_FC_BEAMFORMING_REPORT     0x44  /* Beamforming Report Poll */
#define IEEE80211_FC_VHT_NDP_ANNOUNCE       0x54  /* VHT NDP Announcement */
#define IEEE80211_FC_CTRL_EXT               0x64  /* Control Frame Extension */
#define IEEE80211_FC_CTRL_WRAPPER           0x74  /* Control Wrapper */
#define IEEE80211_FC_BLOCK_ACK_REQ          0x84  /* Block Ack Request (BlockAckReq) */
#define IEEE80211_FC_BLOCK_ACK              0x94  /* Block Ack (BlockAck) */
#define IEEE80211_FC_POLL                   0xA4  /* PS-Poll */
#define IEEE80211_FC_RTS                    0xB4  /* RTS */
#define IEEE80211_FC_CTS                    0xC4  /* CTS */
#define IEEE80211_FC_ACK                    0xD4  /* Ack */
#define IEEE80211_FC_CFEND                  0xE4  /* CF-End */
#define IEEE80211_FC_CFEND_ACK              0xF4  /* CF-End +CF-Ack */


/* Data Frames (Type 10 - Data) */
#define IEEE80211_FC_DATA                   0x08  /* Data */
#define IEEE80211_FC_DATA_CFACK             0x18  /* Data +CF-Ack */
#define IEEE80211_FC_DATA_CFPOLL            0x28  /* Data +CF-Poll */
#define IEEE80211_FC_DATA_CFACKPOLL         0x38  /* Data +CF-Ack +CF-Poll */
#define IEEE80211_FC_NULLFUNC               0x48  /* Null (no data) */
#define IEEE80211_FC_CFACK_NO_DATA          0x58  /* CF-Ack (no data) */
#define IEEE80211_FC_CFPOLL_NO_DATA         0x68  /* CF-Poll (no data) */
#define IEEE80211_FC_CFACKPOLL_NO_DATA      0x78  /* CF-Ack +CF-Poll (no data) */


/* QoS Data Frames (Type 10 - Data with QoS) */
#define IEEE80211_FC_QOS_DATA               0x88  /* QoS Data */
#define IEEE80211_FC_QOS_DATA_CFACK         0x98  /* QoS Data +CF-Ack */
#define IEEE80211_FC_QOS_DATA_CFPOLL        0xA8  /* QoS Data +CF-Poll */
#define IEEE80211_FC_QOS_DATA_CFACKPOLL     0xB8  /* QoS Data +CF-Ack +CF-Poll */
#define IEEE80211_FC_QOS_NULLFUNC           0xC8  /* QoS Null (no data) */
#define IEEE80211_FC_QOS_CFPOLL_NO_DATA     0xE8  /* QoS CF-Poll (no data) */
#define IEEE80211_FC_QOS_CFACKPOLL_NO_DATA  0xF8  /* QoS CF-Ack +CF-Poll (no data) */

#ifndef LE16_DEFINED
#define LE16_DEFINED

typedef uint8_t le8;
typedef uint16_t le16;
typedef uint32_t le32;
typedef uint64_t le64;

#endif

#define fc_type_subtype(a,b) (b << 4) | (a << 2)
#define get_mac(addr) addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]


/*
    IEEE 802.11-2016
    9.2 MAC frame formats
      ╰─> 9.2.4.1.1 General
*/
typedef struct {
    le16 protocol:2;   // Bit's 0-1 (Protocol Version)
    le16 type:2;       // Bit's 2-3 (Type)
    le16 subtype:4;    // Bit's 4-7 (Subtype)
    le16 to_ds:1;      // Bit 8 (To DS)
    le16 from_ds:1;    // Bit 9 (From DS)
    le16 more_frag:1;  // Bit 10 (More Fragments)
    le16 retry:1;      // Bit 11 (Retry)
    le16 pwr_mgmt:1;   // Bit 12 (Power Management)
    le16 more_data:1;  // Bit 13 (More Data)
    le16 protected:1;  // Bit 14 (Protected Frame)
    le16 order:1;      // Bit 15 (Order)
} __attribute__((packed)) FrameControl;


/*
    IEEE 802.11-2016
    9.2 MAC frame formats
      ╰─> 9.2.3 General frame format
*/

/* FrameControl general */
typedef struct {
    FrameControl fc;
    le16 duration;
}__attribute__((packed)) dot11_frame_header;

/* Fragment, squence */
typedef struct {
    le16 frag:4;
    le16 seq:12;
}__attribute__((packed)) fragseq;


/* Management strucures */

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_assoc_req_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_assoc_resp_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_beacon_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_disassoc_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_auth_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
    le16 reason_code;
} __attribute__((packed)) dot11_deauth_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_probe_req_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_probe_resp_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    fragseq frag_seq;
} __attribute__((packed)) dot11_action_frame_header;

typedef struct {
    le16 ess:1;
    le16 ibss:1;
    le16 reserved_1:1;
    le16 reserved_2:1;
    le16 privacy:1;
    le16 short_preamble:1;
    le16 reserved_3:1;
    le16 reserved_4:1;
    le16 spec_man:1;
    le16 qos:1;
    le16 short_slot_time:1;
    le16 apsd:1;
    le16 radio_measurement:1;
    le16 epd:1;
    le16 reserver_5:1;
    le16 reserver_6:1;
} __attribute((packed)) dot11_fixed_params_capabilities;

typedef struct {
    le64 timestamp;
    le16 beacon_interval;
    dot11_fixed_params_capabilities capabilities;
} __attribute__((packed)) dot11_fixed_params;


/* Control structures */

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
} __attribute__((packed)) dot11_ack_frame_header;

typedef struct {
    le16 control;
    fragseq frag_seq;
} __attribute__((packed)) dot11_compressed_block_ack_req;

typedef struct {
    le16 control;
    fragseq frag_seq;
    le64 bitmap;
} __attribute__((packed)) dot11_compressed_block_ack;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    dot11_compressed_block_ack_req compressed_block_ack_req;
} __attribute__((packed)) dot11_block_ack_req_frame_header;

typedef struct {
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    dot11_compressed_block_ack compressed_block_ack;
} __attribute__((packed)) dot11_block_ack_frame_header;


/* Management strutures */


#endif
