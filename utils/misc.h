#ifndef MISC_H
#define MISC_H

extern void mac2str_buf(unsigned char *mac, char delim, char* buf);
extern char *mac2str(unsigned char *mac, char delim);
extern void hexdump(const unsigned char *data, int offset, int len);

#endif