#include "common.h"

void get_phy_for_iface(const char *iface, char *phy, size_t size) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw dev %s info | grep wiphy | awk '{print \"phy\"$2}'", iface);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        return;
    }

    if (fgets(phy, size, fp) != NULL) {
        phy[strcspn(phy, "\n")] = 0; // Убираем \n в конце строки
    }

    pclose(fp);
}

int get_supported_channels(const char *phy, int *channels, int max_channels) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "iw phy %s info", phy);
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        return 0;
    }

    char line[256];
    int in_frequencies = 0, count = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (strstr(line, "Frequencies:")) {
            in_frequencies = 1;
            continue;
        }
        if (strstr(line, "(no IR)")) {
            continue;
        }
        if (in_frequencies) {
            if (strstr(line, "MHz")) {
                int freq, channel;
                if (sscanf(line, " * %*d MHz [%d]", &channel) == 1) { 
                    //channel = (freq - 2407) / 5; // Конвертируем в канал
                    if (channel > 0 && count < max_channels) {
                        channels[count++] = channel;
                    }
                }
            }
        }
    }

    pclose(fp);
    return count; // Возвращаем количество каналов
}

int mac80211_set_channel(const char *iface, int channel) {
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "iw dev %s set channel %d", iface, channel); 
    
    FILE *fp = popen(cmd, "r");
    if (!fp) {
        perror("popen");
        return -1;
    }

    char output[256];
    if (fgets(output, sizeof(output), fp) != NULL) {
        if (strstr(output, "No such device") || strstr(output, "command failed: No such device")) {
            pclose(fp);
            pthread_exit(NULL);
        }
    }
    
    pclose(fp);
    return 0;
    //system(cmd);
}

void *channel_hopper(void *arg) {
    const char *iface = (const char *)arg;
    char phy[16];
    int channels[64];
    get_phy_for_iface(iface, phy, sizeof(phy));
    int channels_count = get_supported_channels(phy, channels, 64);


   // printf("cnt: %d", channels_count);
   // for (int i = 0; i < channels_count; i++) {
   //     printf("Channel: %d\n", channels[i]);
   // }

    while (1) {
        for (int i = 0; i < channels_count; i++) {
            int channel = channels[i];
            if (mac80211_set_channel(iface, channel) != 0) {
                break;
            }
            sleep(1);
        }
    }

    return NULL;
}