#include <stdio.h>
#include "misc.h"

/* Converts a raw MAC address to a colon-delimited string */
/* buf holds the result & needs to be 18 bytes */
void mac2str_buf(unsigned char *mac, char delim, char* buf) {
#define PAT "%.2X%c"
#define PRT(X) mac[X], delim
#define PBT "%.2X"
	if(delim)
		sprintf(buf, PAT PAT PAT PAT PAT PBT, PRT(0), PRT(1), PRT(2), PRT(3), PRT(4), mac[5]);
	else
		sprintf(buf, PBT PBT PBT PBT PBT PBT, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Converts a raw MAC address to a colon-delimited string */
char *mac2str(unsigned char *mac, char delim) {
	char nyu[6*3];
	mac2str_buf(mac, delim, nyu);
	return strdup(nyu);
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
			//printf("");
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