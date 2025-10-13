CC = gcc
CFLAGS = -Wall -g

.PHONY: all clean

all: raw_socket_capture

raw_socket_capture: raw_socket_capture.c
	$(CC) $(CFLAGS) -o raw_socket_capture raw_socket_capture.c

clean:
	rm -f raw_socket_capture

run:
	sudo ./raw_socket_capture