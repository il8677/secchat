.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server

clean:
	rm -f server client *.o *.db*
	rm -rf serverkeys ttpkeys clientkeys

ui.o: ui.c ui.h

client.o: client.c api.h ui.h util.h

api.o: api.c api.h 

db.o: db.c db.h errcodes.h api.h

server.o: server.c util.h db.h errcodes.h keys-server

util.o: util.c util.h

worker.o: worker.c util.h worker.h errcodes.h db.h

client: client.o api.o ui.o util.o

server: server.o api.o util.o worker.o db.o 

keys-server: keys-ttp
	python3 ttp.py server

keys-ttp:
	python3 ttp.py ttp