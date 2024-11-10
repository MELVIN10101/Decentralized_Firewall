CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap

SRC = src/main.c src/DPI/packet_capture.c
OBJ = $(SRC:.c=.o)

packet_capture: $(OBJ)
	$(CC) -o packet_capture $(OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) packet_capture
