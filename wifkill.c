#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "utils/misc.h"
#include "radiotap/radiotap.h"
#include "utils/defs.h"
#include "utils/colors.h"
#include "utils/wpsmon_progress.h"


#define MAX_MACS 250
int use_colors = 1;

typedef struct {
	unsigned char mac[MAC_ADDR_LEN];
} mac_entry;

mac_entry seen_ap_list[MAX_MACS];
int mac_count = 0;

int is_mac_exists(uint8_t *mac) {
	for (int i = 0; i < mac_count; i++) {
		if (memcmp(seen_ap_list[i].mac, mac, MAC_ADDR_LEN) == 0) {
			return 1;
		}
	}

	return 0;
}

void mac_add(uint8_t *mac) {
	if (mac_count < MAX_MACS) {
		memcpy(seen_ap_list[mac_count].mac, mac, MAC_ADDR_LEN);
		mac_count++;
	}
}

void hexdump(const unsigned char *data, int offset, int len) {
    printf("\n");
    char ascii[17];  // 16 байт + '\0'
    int idx = 0;

    for (int i = offset; i < len; ++i) {
        // Печатаем адрес с учётом offset
        if ((i - offset) % 16 == 0) {
            printf("\e[1;32m%04x\e[0;0m  ", i - offset);
        }

        // Печатаем данные в шестнадцатеричном виде
        printf("\e[1;36m%02x ", data[i]);

        // Заполняем массив для вывода ASCII-символов
        if (data[i] >= 32 && data[i] <= 126) {
            ascii[(i - offset) % 16] = data[i];  // используем i - offset, чтобы не выйти за пределы
        } else {
            ascii[(i - offset) % 16] = '.';  // заменяем непечатаемые символы на '.'
        }

		if ((i - offset + 1) % 8 == 0) {
			printf("");
		}
		
        // Когда дойдем до 16 байта или конца, печатаем ASCII строку
        if ((i - offset + 1) % 16 == 0 || i + 1 == len) {
            // Завершаем строку для вывода
            ascii[(i - offset) % 16] = '\0';  // Обеспечиваем корректный null-терминатор

            // Дополняем недостающие байты пробелами для неполных строк
            int missing_spaces = (16 - ((i - offset + 1) % 16)) % 16;
            for (int j = 0; j < missing_spaces; ++j) {
                printf("   ");  // пробелы для недостающих байт
            }

            printf("\e[0;0m | \e[1;31m%s\e[0;0m", ascii);  // Выводим ASCII
            printf("\n");
        }

        ++idx;
    }

    printf("\n");
}

void print_header() {
	fprintf  (stdout, HEAD_COLOR);
	fprintf  (stdout, "BSSID               Ch    Signal strength    dBm    Frequency    WPS  Lck  Vendor    ESSID\n");
	fprintf  (stdout, LINE_COLOR);
	fprintf  (stdout, "-----------------------------------------------------------------------------------------------\n");
	fprintf  (stdout, RESET_COLOR);
}

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
	static const struct vendor vendors[] = {
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
	for (int i = 0; i < elt -> count; i++) {
		uint8_t *elt_info = elt-> elt[i].data;
		uint8_t elt_id = elt -> elt[i].id;
		uint8_t elt_len = elt -> elt[i].len;
		
		if (elt_id == 0) {
			static char ssid[33];
			snprintf(ssid, sizeof(ssid), "%.*s", elt_len, elt_info);
			return ssid; 
		}
	}

	return "<hidden>";
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	ieee80211_radiotap_data_t rt_data;
	if (radiotap_parse(packet, &rt_data) == 0) {	
		int next_offset = rt_data.rt_header -> it_len;

		uint8_t idx = 0;
		dot11_mgmt_frame_header *dot11_mgmt_frame = (dot11_mgmt_frame_header *)(packet + next_offset);
		uint8_t type_subtype = fc_type_subtype(dot11_mgmt_frame -> fc.type, dot11_mgmt_frame -> fc.subtype);

		if (type_subtype == IEEE80211_FC_BEACON) {
			next_offset += sizeof(dot11_mgmt_frame_header) + sizeof(dot11_fixed_params);
			int elt_offset = next_offset;
			dot11_elt_t dot11_elt = {0};

;			while (next_offset + 2 <= h -> len) {
				uint8_t TAG_ID = packet[next_offset];
				uint8_t TAG_LEN = packet[next_offset +1];
				
				dot11_elt_entry *elt = &dot11_elt.elt[dot11_elt.count];
				elt -> id = TAG_ID;
				elt -> len = TAG_LEN;
				memcpy(elt -> data, &packet[next_offset +2], TAG_LEN);
				dot11_elt.count++;

				next_offset += 2 + TAG_LEN;
			}

			
			uint8_t *bssid = dot11_mgmt_frame -> addr3;

			if (!is_mac_exists(bssid)) {
				char *bssid_str = mac2str(bssid, ':');
				uint8_t channel = rt_data.channel;
				char *ssid;
				char *lock_display;
				char *hardware;
				char *rssi_color = NULL;
				char *wps_version;
				int progress_dbm = 0;
				int dbm = 0;
				int rssi = 0;
				double freq = 0;
				wps_info_t wps_info;

				ssid = get_ap_ssid(&dot11_elt);
				parse_wps_wps_params(&dot11_elt, &wps_info);
				hardware = get_hardware_name(&dot11_elt);
	
				if (wps_info.is_wps) {
					if (wps_info.locked) lock_display = "Yes";
					else lock_display = "No ";
					if (wps_info.version == 1) wps_version = "1.0";
					else if (wps_info.version == 2) wps_version = "2.0";
					else wps_version = "1.0";
				} else {
					lock_display = "-  ";
					wps_version = "-  ";
				}
				freq = (double)rt_data.channel_frequency / 1000;
				rssi = rt_data.dbm_Antenna_Signal;
				dbm = -rssi;
				progress_dbm = dbm;
				
				if (progress_dbm <= 40) progress_dbm = 40;
				
				int wps_signal_progess_idx = floor(((progress_dbm - dbm_max) * dbm_array_max_idx) / (dbm_min - dbm_max));
				
				if (use_colors) {
					if (progress_dbm >= 30 && progress_dbm <= 69) rssi_color = COLOR_GREEN;
					if (progress_dbm >= 70 && progress_dbm <= 85) rssi_color = COLOR_BYELLOW;
					if (progress_dbm >= 86 && progress_dbm <= 99) rssi_color = COLOR_BRED;
				} else {
					rssi_color = RESET_COLOR;
				}
	
				char* signal_dbm = wps_signal_progess[wps_signal_progess_idx];

				mac_add(bssid);
				if (wps_info.is_wps) {
					fprintf(stdout, "%s%17s%s ", BSSID_COLOR, bssid_str, RESET_COLOR);
					fprintf(stdout, "%s%3d%s  ", CHANNEL_COLOR, channel, RESET_COLOR);
					fprintf(stdout, "%s%20s%s ", rssi_color, signal_dbm, RESET_COLOR);
					fprintf(stdout, "%s%.2d%s  ", RSSI_COLOR, rssi, RESET_COLOR);
					fprintf(stdout, "%s  %.3f GHz  %s  ", FREQ_COLOR, freq, RESET_COLOR);
					fprintf(stdout, "%s%3s%s  ", WPS_VER_COLOR, wps_version, RESET_COLOR);
					fprintf(stdout, "%s%3s%s ", WPS_LCK_COLOR, lock_display, RESET_COLOR);
					fprintf(stdout, " %s%8s%s  ", VENDOR_COLOR, hardware, RESET_COLOR);
					fprintf(stdout, "%s%s%s", ESSID_COLOR, ssid, RESET_COLOR);	

					fprintf(stdout, "\n");
				}
			}
			
		}

	} else {
		
	}

	//printf("\n\n");
}

int main() {
	print_header();
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = "wlan0mon";
    
	//handle = pcap_open_live(dev, BUFSIZ, 1000, 1, errbuf);
	handle = pcap_open_offline("pcap/8146packets_dump.pcapng", errbuf);
	//handle = pcap_open_offline("pcap/test.pcapng", errbuf);

	if (handle == NULL) {
		printf("Error opening device %s\n", errbuf);
		return 1;
	}

	if (pcap_loop(handle, 0, packet_handler, NULL)) {
		printf("Error capturing packets: %s\n", pcap_geterr(handle));
		return 1;
	}
	
	pcap_close(handle);
	return 1;
	
}
