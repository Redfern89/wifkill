#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "radiotap/radiotap.h"
#include "utils/dot11.h"

int is_beacon_frame(const uint8_t *packet, uint8_t rt_len) {
	uint16_t frame_control = ntohs	(*(uint16_t *)(packet + rt_len));
	return (frame_control & 0xFF7C) == 0x8000;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	ieee80211_radiotap_data_t data;
	if (radiotap_parse(packet, &data) == 0) {	
		int next_offset = data.rt_header -> it_len;

		uint8_t idx = 0;
/*		dot11_frame_header *dot11_frame = malloc(sizeof(dot11_frame_header));
		memset(&dot11_frame, 0, sizeof(dot11_frame_header));
		dot11_frame = (dot11_frame_header *)(packet + data.rt_header -> it_len);	
		printf("type=%06x\n", dot11_frame->addr1);
*/
		dot11_frame_header *dot11_frame = (dot11_frame_header *)(packet + data.rt_header->it_len);

		printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
			dot11_frame->addr1[0], dot11_frame->addr1[1], dot11_frame->addr1[2], 
			dot11_frame->addr1[3], dot11_frame->addr1[4], dot11_frame->addr1[5]);
	 
		
		for (int i = next_offset; i < h -> len; i++) {
			if ((idx) % 16 == 0) printf("%04x  ", idx);
			printf("%02x ", (packet[i]));
			if ((idx + 1) % 8 == 0) printf("  ");
			if ((idx + 1) % 16 == 0) printf("\n");
			idx++;
		}

	} else {
		
	}

	printf("\n\n");
}

int main() {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = "radio0mon";
    
	//handle = pcap_open_live(dev, BUFSIZ, 1000, 1, errbuf);
	handle = pcap_open_offline("test.pcapng", errbuf);
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
