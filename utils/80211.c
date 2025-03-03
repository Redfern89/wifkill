#include "80211.h"
#define _GNU_SOURCE
#include <string.h>


void parse_wps_wps_params(dot11_elt_t *elt, wps_info_t *wps_info) {
	memset(wps_info, 0, sizeof(wps_info_t));
	wps_info -> version = 0;
	wps_info -> is_wps = 0;

	for (int i = 0; i < elt -> count; i++) {
		uint8_t *elt_info = elt-> elt[i].data;
		uint8_t elt_id = elt -> elt[i].id;
		uint8_t elt_len = elt -> elt[i].len;

		if (elt_id == 221 && memcmp(elt_info, WPS_IE, 4) == 0) {
			wps_info -> is_wps = 1;
			if (memmem(elt_info, elt_len, WPLS_LOCKED, 5)) {
				wps_info -> locked = 1;
			}

			if (memmem(elt_info, elt_len, WPS_RF_BANDS, 2) && memmem(elt_info, elt_len, WPS_RF_BANDS, 2)) {
				wps_info -> version = 2;
			} else if (memmem(elt_info, elt_len, WPS_VERSION, 2)) {
				wps_info -> version = 1;
			}
		}
	}
}

char *get_hardware_name(dot11_elt_t *elt) {
	struct vendor {
		unsigned char id[3];
		char name[9];
	};
	static struct vendor vendors[] = {
		{"\x00\x10\x18", "Broadcom"}, // Broadcom
		{"\x00\x03\x7f", "AtherosC"}, // Atheros Communications
		{"\x00\x13\x74", "AtherosC"}, // Atheros Communications
		{"\x00\x0c\x43", "RalinkTe"}, // Ralink Technology, Corp.
		{"\x00\x17\xa5", "RalinkTe"}, // Ralink Technology, Corp.
		{"\x00\xe0\x4c", "RealtekS"}, // Realtek Semiconductor Corp.
		{"\x00\xa0\x00", "Mediatek"}, // Mediatek Corp.
		{"\x00\x0c\xe7", "Mediatek"}, // Mediatek Corp.
		{"\x00\x1c\x51", "CelenoCo"}, // Celeno Communications, Inc
		{"\x00\x50\x43", "MarvellS"}, // Marvell Semiconductor, Inc.
		{"\x00\x26\x86", "Quantenn"}, // Quantenna Communications, Inc
		{"\x00\x09\x86", "LantiqML"}, // Lantiq/MetaLink
		{"\x00\x50\xf2", "Microsof"}, // Microsoft
		{"\xac\x85\x3d", "HuaweiTe"}, // Huawei Technologies Co., Ltd
		{"\x88\x12\x4e", "Qualcomm"}, // Qualcomm Atheros
		{"\x8c\xfd\xf0", "Qualcomm"}, // Qualcomm, Inc
		{"\x00\xa0\xcc", "Lite-OnC"}, // Lite-On Communications, Inc
		{"\x40\x45\xda", "SpreadTe"}, // Spreadtrum Technology, Inc
		{"\x50\x6f\x9a", "Wi-FiAli"}  // Wi-Fi Aliance			
	};
	#define VENDORS_COUNT (sizeof(vendors) / sizeof(vendors[0]))

	for (int i = 0; i < elt -> count; i++) {
		uint8_t *elt_info = elt-> elt[i].data;
		uint8_t elt_id = elt -> elt[i].id;
		uint8_t elt_len = elt -> elt[i].len;
		
		
		if (elt_id == 221 && (elt_len > 6 && elt_len <= 9)) {
			for (size_t j = 0; j < VENDORS_COUNT; j++) {
				if (memcmp(elt_info, vendors[j].id, 3) == 0) {
					return vendors[j].name;
				}
			}
		}
	}
	return "Unknown ";
}

char *get_ap_ssid(dot11_elt_t *elt) {
	static char ssid[33];
    for (int i = 0; i < elt -> count; i++) {
		uint8_t *elt_info = elt-> elt[i].data;
		uint8_t elt_id = elt -> elt[i].id;
		uint8_t elt_len = elt -> elt[i].len;
		
		if (elt_id == 0) {
			snprintf(ssid, sizeof(ssid), "%.*s", elt_len, elt_info);
			return (char *)ssid; 
		}
	}

	return strncpy(ssid, "<hidden>", sizeof(ssid));
}