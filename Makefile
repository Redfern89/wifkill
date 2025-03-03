CC = gcc
CFLAGS = -Wall -Wextra -w -O2 -I./radiotap
LDFLAGS = -lpcap
OBJ = wifkill.o radiotap/radiotap.o utils/misc.o
TARGET = wifkill

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)


radiotap/radiotap.o: radiotap/radiotap.c
	$(CC) $(CFLAGS) -c radiotap/radiotap.c -o radiotap/radiotap.o

utils/misc.o: utils/misc.c
	$(CC) $(CFLAGS) -c utils/misc.c -o utils/misc.o

wifkill.o: wifkill.c
	$(CC) $(CFLAGS) -c wifkill.c -o wifkill.o

clean:
	rm -f $(OBJ) $(TARGET)
