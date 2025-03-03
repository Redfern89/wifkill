#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

extern int mac80211_set_channel(const char *iface, int channel);
extern void *channel_hopper(void *arg);

#endif /* COMMON_H */