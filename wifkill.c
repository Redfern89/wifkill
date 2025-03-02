#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "radiotap/radiotap.h"
#include "utils/dot11.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	ieee80211_radiotap_data_t data;
	if (radiotap_parse(packet, &data) == 0) {	
		int next_offset = data.rt_header -> it_len;

		uint8_t idx = 0;
		dot11_frame_header *dot11_frame = (dot11_frame_header *)(packet + next_offset);
		uint8_t type_subtype = fc_type_subtype(dot11_frame -> fc.type, dot11_frame -> fc.subtype);
		next_offset += 4;

		if (type_subtype == IEEE80211_FC_BEACON) {

			dot11_beacon_frame_header *dot11_beacon = (dot11_beacon_frame_header *)(packet + next_offset);
			printf("frag: %d, seq: %d\n", dot11_beacon -> frag_seq.frag, dot11_beacon -> frag_seq.seq );
			
			printf(MAC_ADDR_FMT, get_mac(dot11_beacon -> addr1));
			printf("\n");
			printf(MAC_ADDR_FMT, get_mac(dot11_beacon -> addr2));
			printf("\n");
			printf(MAC_ADDR_FMT, get_mac(dot11_beacon -> addr3));
			/*
			for (int i = next_offset; i < h -> len; i++) {
				if ((idx) % 16 == 0) printf("%04x  ", idx);
				printf("%02x ", (packet[i]));
				if ((idx + 1) % 8 == 0) printf("  ");
				if ((idx + 1) % 16 == 0) printf("\n");
				idx++;
			}
			*/
		}

	} else {
		
	}

	//printf("\n\n");
}

int main() {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = "radio0mon";
    
	//handle = pcap_open_live(dev, BUFSIZ, 1000, 1, errbuf);
	handle = pcap_open_offline("pcap/test.pcapng", errbuf);
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
