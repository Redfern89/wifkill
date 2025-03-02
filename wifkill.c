#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "radiotap/radiotap.h"
#include "utils/defs.h"

#include <stdio.h>
#include <stdio.h>

#include <stdio.h>

#include <stdio.h>

#include <stdio.h>

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



void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
	ieee80211_radiotap_data_t data;
	if (radiotap_parse(packet, &data) == 0) {	
		int next_offset = data.rt_header -> it_len;

		uint8_t idx = 0;
		dot11_mgmt_frame_header *dot11_mgmt_frame = (dot11_mgmt_frame_header *)(packet + next_offset);
		uint8_t type_subtype = fc_type_subtype(dot11_mgmt_frame -> fc.type, dot11_mgmt_frame -> fc.subtype);

		if (type_subtype == IEEE80211_FC_BEACON) {

			//dot11_mgmt_frame_header *dot11_beacon = (dot11_mgmt_frame_header *)(packet + next_offset);
			printf("frag: %d, seq: %d\n", dot11_mgmt_frame -> frag_seq.frag, dot11_mgmt_frame -> frag_seq.seq );
			
			
			printf(MAC_ADDR_FMT, get_mac(dot11_mgmt_frame -> addr1));
			printf("\n");
			printf(MAC_ADDR_FMT, get_mac(dot11_mgmt_frame -> addr2));
			printf("\n");
			printf(MAC_ADDR_FMT, get_mac(dot11_mgmt_frame -> addr3));
			
			next_offset += sizeof(dot11_mgmt_frame_header) + sizeof(dot11_fixed_params);
			
			printf("\n");
			hexdump(packet, 0, h -> len);

			printf("\n");
			
			while (next_offset + 2 <= h -> len) {
				uint8_t TAG_ID = packet[next_offset];
				uint8_t TAG_LEN = packet[next_offset +1];
				
				printf("Tag: %d (len=%d)\n", TAG_ID, TAG_LEN);

				next_offset += 2 + TAG_LEN;
			}
			
		}

	} else {
		
	}

	//printf("\n\n");
}

int main() {
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev = "wlan0mon";
    
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
