CC = gcc
CFLAGS = -Wall -Wextra -Wno-unused-variable -O2 -I./radiotap -I /usr/include/libnl3/
LDFLAGS = -lpcap
OBJ = wifkill.o radiotap/radiotap.o utils/misc.o utils/80211.o utils/common.o
TARGET = wifkill

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)


radiotap/radiotap.o: radiotap/radiotap.c
	$(CC) $(CFLAGS) -c radiotap/radiotap.c -o radiotap/radiotap.o

utils/misc.o: utils/misc.c
	$(CC) $(CFLAGS) -c utils/misc.c -o utils/misc.o

utils/80211.o: utils/80211.c
	$(CC) $(CFLAGS) -c utils/80211.c -o utils/80211.o

utils/common.o: utils/common.c
	$(CC) $(CFLAGS) -c utils/common.c -o utils/common.o


wifkill.o: wifkill.c
	$(CC) $(CFLAGS) -c wifkill.c -o wifkill.o

clean:
	rm -f $(OBJ) $(TARGET)
