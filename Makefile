.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server

clean:
	rm -f server client *.o chat.db 

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h

api.o: api.c api.h 

server.o: server.c util.h

util.o: util.c util.h

worker.o: worker.c util.h worker.h

client: client.o api.o ui.o util.o

server: server.o api.o util.o worker.o



