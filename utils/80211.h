#ifndef IEEE80211_H
#define IEEE80211_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"

extern void parse_wps_wps_params(dot11_elt_t *elt, wps_info_t *wps_info);
extern char *get_hardware_name(dot11_elt_t *elt); 
extern char *get_ap_ssid(dot11_elt_t *elt);

#endif /* IEEE80211_H */