#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <getopt.h>
#include "radiotap/radiotap.h"
#include "utils/common.h"
#include "utils/misc.h"
#include "utils/defs.h"
#include "utils/colors.h"
#include "utils/wpsmon_progress.h"
#include "utils/80211.h"


#define MAX_MACS 250
int use_colors = 1;
int capture_all = 0;

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
		
		/* GLOBULE */
		if (type_subtype == IEEE80211_FC_BEACON || type_subtype == IEEE80211_FC_PROBE_RESP) {
			next_offset += sizeof(dot11_mgmt_frame_header) + sizeof(dot11_fixed_params);
			int elt_offset = next_offset;
			dot11_elt_t dot11_elt = {0};

			while (next_offset + 2 <= h -> len) {
				uint8_t TAG_ID = packet[next_offset];
				uint8_t TAG_LEN = packet[next_offset +1];
				
				dot11_elt_entry *elt = &dot11_elt.elt[dot11_elt.count];
				elt -> id = TAG_ID;
				elt -> len = TAG_LEN;
				memcpy(elt->data, packet + next_offset + 2, elt->len);
				//memcpy(elt -> data, &packet[next_offset +2], TAG_LEN);
				dot11_elt.count++;
				next_offset += 2 + TAG_LEN;
			}

			
			uint8_t *bssid = dot11_mgmt_frame -> addr3;

			if (!is_mac_exists(bssid)) {
				mac_add(bssid);
				char *bssid_str = mac2str(bssid, ':');
				uint8_t channel = rt_data.channel;
				double freq = (double)rt_data.channel_frequency / 1000;
				int rssi = rt_data.dbm_Antenna_Signal;
				int dbm = -rssi;
				int progress_dbm = dbm <= 40 ? 40 : dbm;
				int wps_signal_progess_idx = floor(((progress_dbm - dbm_max) * dbm_array_max_idx) / (dbm_min - dbm_max));
				char *signal_dbm = wps_signal_progess[wps_signal_progess_idx];
				char print_ap = 0;
				char *ssid = get_ap_ssid(&dot11_elt);
				wps_info_t wps_info;
				parse_wps_wps_params(&dot11_elt, &wps_info);
				char *hardware = get_hardware_name(&dot11_elt);
				char *lock_display = (wps_info.is_wps ? (wps_info.locked ? "Yes" : "No ") : "-  ");
				char *wps_version = (wps_info.is_wps ? (wps_info.version == 2 ? "2.0" : "1.0") : "-  ");

				char *rssi_color = use_colors
					? (progress_dbm >= 86 ? COLOR_BRED :
						progress_dbm >= 70 ? COLOR_BYELLOW :
						progress_dbm >= 30 ? COLOR_GREEN : RESET_COLOR)
					: RESET_COLOR;
			
				if (capture_all == 1) {
					print_ap = 1;
				} else if (capture_all == 0 && wps_info.is_wps) {
					print_ap = 1;
				}

				if (print_ap) {
					fprintf(stdout, "%s%17s%s %s%3d%s  %s%20s%s %s%.2d%s  %s  %.3f GHz  %s  %s%3s%s  %s%3s%s  %s%8s%s  %s%s%s\n",
						BSSID_COLOR, bssid_str, RESET_COLOR,
						CHANNEL_COLOR, channel, RESET_COLOR,
						rssi_color, signal_dbm, RESET_COLOR,
						RSSI_COLOR, rssi, RESET_COLOR,
						FREQ_COLOR, freq, RESET_COLOR,
						WPS_VER_COLOR, wps_version, RESET_COLOR,
						WPS_LCK_COLOR, lock_display, RESET_COLOR,
						VENDOR_COLOR, hardware, RESET_COLOR,
						ESSID_COLOR, ssid, RESET_COLOR);
				}
			}
			
			
		}

	} else {
		
	}

}

int main(int argc, char *argv[]) {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *pcapfile = NULL;
	char *interface = NULL;
	char use = 0;
	
    static struct option long_options[] = {
		{"interface", required_argument, 0, 'i'},
		{"file", required_argument, 0, 'f'},
		{"capture-all", no_argument, 0, 'a'}
	};

	int opt;
	while ((opt = getopt_long(argc, argv, "i:f:a", long_options, NULL)) != -1) {
		switch (opt) {
			case 'i':
				interface = optarg;
				use = 1;
				break;
			case 'f':
				pcapfile = optarg;
				use = 2;
				break;
			case 'a':
				capture_all = 1;
				break;
			default:
				fprintf(stderr, "Использование: %s -i <интерфейс> или [-f <pcap-файл>]\n", argv[0]);
				exit(1);
		}
	}
	
	if (use == 0) {
		fprintf(stderr, "Использование: -i <интерфейс> или [-f <pcap-файл>]\n");
		exit(1);
	}

	if (use == 1) {
		pthread_t thread;
		if (pthread_create(&thread, NULL, channel_hopper, (void *)interface) != 0) {
			perror("pthread_create");
			return 1;
		}
		handle = pcap_open_live(interface, BUFSIZ, 1000, 1, errbuf);
		if (handle == NULL) {
			printf("Error opening device %s\n", errbuf);
			return 1;
		}
	} else if (use == 2) {
		handle = pcap_open_offline(pcapfile, errbuf);
		if (handle == NULL) {
			printf("Error opening device %s\n", errbuf);
			return 1;
		}
	}


	print_header();
	if (pcap_loop(handle, 0, packet_handler, NULL)) {
		printf("Error capturing packets: %s\n", pcap_geterr(handle));
		return 1;
	}
	
	pcap_close(handle);
	//pthread_join(thread, NULL); 

	return 0;	
}
