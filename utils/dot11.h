#ifndef DOT11_UTILS_H
#define DOT11_UTILS_H

#include <stdio.h>
#include <stdint.h>

#define MAC_ADDR_LEN 6

/* Management Frames (Type 00 - Management) */
#define IEEE80211_FC_ASSOC_REQ		    0x0000  /* Association Request */
#define IEEE80211_FC_ASSOC_RESP		    0x0010  /* Association Response */
#define IEEE80211_FC_REASSOC_REQ		0x0020  /* Reassociation Request */
#define IEEE80211_FC_REASSOC_RESP	    0x0030  /* Reassociation Response */
#define IEEE80211_FC_PROBE_REQ		    0x0040  /* Probe Request */
#define IEEE80211_FC_PROBE_RESP		    0x0050  /* Probe Response */
#define IEEE80211_FC_BEACON			    0x0080  /* Beacon */
#define IEEE80211_FC_ATIM			    0x0090  /* ATIM */
#define IEEE80211_FC_DISASSOC		    0x00A0  /* Disassociation */
#define IEEE80211_FC_AUTH			    0x00B0  /* Authentication */
#define IEEE80211_FC_DEAUTH			    0x00C0  /* Deauthentication */
#define IEEE80211_FC_ACTION			    0x00D0  /* Action */

/* Control Frames (Type 01 - Control) */
#define IEEE80211_FC_BACK_REQ		    0x0480  /* Block Ack Request */
#define IEEE80211_FC_BACK			    0x0490  /* Block Ack */
#define IEEE80211_FC_PSPOLL			    0x04A0  /* PS-Poll */
#define IEEE80211_FC_RTS		        0x04B0  /* RTS (Request to Send) */
#define IEEE80211_FC_CTS				0x04C0  /* CTS (Clear to Send) */
#define IEEE80211_FC_ACK				0x04D0  /* ACK (Acknowledgment) */
#define IEEE80211_FC_CFEND			    0x04E0  /* CF-End */
#define IEEE80211_FC_CFENDACK		    0x04F0  /* CF-End + CF-Ack */

/* Data Frames (Type 10 - Data) */
#define IEEE80211_FC_DATA			    0x0880  /* Data */
#define IEEE80211_FC_DATA_CFACK		    0x0890  /* Data + CF-Ack */
#define IEEE80211_FC_DATA_CFPOLL		0x08A0  /* Data + CF-Poll */
#define IEEE80211_FC_DATA_CFACKPOLL	    0x08B0  /* Data + CF-Ack + CF-Poll */
#define IEEE80211_FC_NULLFUNC		    0x08C0  /* Null Data */
#define IEEE80211_FC_CFACK			    0x08D0  /* CF-Ack (No Data) */
#define IEEE80211_FC_CFPOLL			    0x08E0  /* CF-Poll (No Data) */
#define IEEE80211_FC_CFACKPOLL		    0x08F0  /* CF-Ack + CF-Poll (No Data) */
#define IEEE80211_FC_QOS_DATA		    0x0980  /* QoS Data */
#define IEEE80211_FC_QOS_DATA_CFACK	    0x0990  /* QoS Data + CF-Ack */
#define IEEE80211_FC_QOS_DATA_CFPOLL	0x09A0  /* QoS Data + CF-Poll */
#define IEEE80211_FC_QOS_DATA_CFACKPOLL	0x09B0  /* QoS Data + CF-Ack + CF-Poll */
#define IEEE80211_FC_QOS_NULLFUNC	    0x09C0  /* QoS Null Data */
#define IEEE80211_FC_QOS_CFACK		    0x09D0  /* QoS CF-Ack (No Data) */
#define IEEE80211_FC_QOS_CFPOLL		    0x09E0  /* QoS CF-Poll (No Data) */
#define IEEE80211_FC_QOS_CFACKPOLL	    0x09F0  /* QoS CF-Ack + CF-Poll (No Data) */


#ifndef LE16_DEFINED
#define LE16_DEFINED

typedef uint8_t le8;
typedef uint16_t le16;
typedef uint32_t le32;
typedef uint64_t le64;

#endif

typedef struct {
    le8 type;
    le8 subtype;
} __attribute__((packed)) FrameControl;


typedef struct {
    FrameControl fc;
    le16 duration;
    uint8_t addr1[MAC_ADDR_LEN];
    uint8_t addr2[MAC_ADDR_LEN];
    uint8_t addr3[MAC_ADDR_LEN];
    le16 frag_seq;
} __attribute__((packed)) dot11_frame_header;


#endif