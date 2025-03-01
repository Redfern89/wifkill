CC = gcc
CFLAGS = -Wall -Wextra -w -O2 -I./radiotap
LDFLAGS = -lpcap
OBJ = wifkill.o radiotap/radiotap.o
TARGET = wifkill

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)


radiotap/radiotap.o: radiotap/radiotap.c
	$(CC) $(CFLAGS) -c radiotap/radiotap.c -o radiotap/radiotap.o

wifkill.o: wifkill.c
	$(CC) $(CFLAGS) -c wifkill.c -o wifkill.o

clean:
	rm -f $(OBJ) $(TARGET)
