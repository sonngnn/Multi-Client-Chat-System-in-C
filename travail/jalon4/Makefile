CFLAGS=-Wall

all: client server

client: client.c common.h msg_struct.h
	gcc $(CFLAGS) -o client client.c

server: server.c common.h msg_struct.h
	gcc $(CFLAGS) -o server server.c

clean:
	rm -f client server
