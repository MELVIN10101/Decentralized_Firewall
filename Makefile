CC = gcc
CFLAGS = -Wall -g
INCLUDE = -Iinclude -Isrc/DPI
SRC_DIR = src/DPI
OBJ_DIR = obj
LDFLAGS = -lpcap

OBJ = $(OBJ_DIR)/packet_capture.o $(OBJ_DIR)/packet_parser.o $(OBJ_DIR)/traffic_classification.o 

all: main

main: main.o $(OBJ)
	$(CC) $(CFLAGS) main.o $(OBJ) -o main -lpcap

main.o: main.c
	$(CC) $(CFLAGS) $(INCLUDE) -c main.c -o main.o

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@

clean:
	rm -rf main *.o $(OBJ_DIR)
