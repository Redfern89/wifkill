#include "misc.h"

/* Converts a raw MAC address to a colon-delimited string */
/* buf holds the result & needs to be 18 bytes */
void mac2str_buf(unsigned char *mac, char delim, char* buf)
{
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