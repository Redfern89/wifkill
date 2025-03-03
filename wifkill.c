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
#include "utils/80211.h"
#include <math.h>


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

void print_header() {
	fprintf  (stdout, HEAD_COLOR);
	fprintf  (stdout, "BSSID               Ch    Signal strength    dBm    Frequency    WPS  Lck  Vendor    ESSID\n");
	fprintf  (stdout, LINE_COLOR);
	fprintf  (stdout, "-----------------------------------------------------------------------------------------------\n");
	fprintf  (stdout, RESET_COLOR);
}


void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	(void)user; 
	ieee80211_radiotap_data_t rt_data;
	if (radiotap_parse(packet, &rt_data) == 0) {	
		unsigned int next_offset = rt_data.rt_header -> it_len;
		dot11_mgmt_frame_header *dot11_mgmt_frame = (dot11_mgmt_frame_header *)(packet + next_offset);
		uint8_t type_subtype = fc_type_subtype(dot11_mgmt_frame -> fc.type, dot11_mgmt_frame -> fc.subtype);

		if (type_subtype == IEEE80211_FC_BEACON) {
			next_offset += sizeof(dot11_mgmt_frame_header) + sizeof(dot11_fixed_params);
			int elt_offset = next_offset;
			dot11_elt_t dot11_elt = {0};

			while (next_offset + 2 <= h -> len) {
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
				char *ssid = NULL;
				char *lock_display = NULL;
				char *hardware = {0};
				char *rssi_color = NULL;
				char *wps_version = NULL;
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
