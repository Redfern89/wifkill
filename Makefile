CC = gcc
CFLAGS = -Wall -Wextra -w -O2 -I./radiotap  # Указываем путь для заголовочных файлов
LDFLAGS = -lpcap
OBJ = wifkill.o radiotap/radiotap.o  # Указываем путь для исходников
TARGET = wifkill

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

# Компиляция объектов из radiotap/ с учетом пути
radiotap/radiotap.o: radiotap/radiotap.c
	$(CC) $(CFLAGS) -c radiotap/radiotap.c -o radiotap/radiotap.o

wifkill.o: wifkill.c
	$(CC) $(CFLAGS) -c wifkill.c -o wifkill.o

clean:
	rm -f $(OBJ) $(TARGET)
