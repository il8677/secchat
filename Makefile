.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl

all: client server

clean:
	rm -f server client *.o *.db*
	rm -rf serverkeys ttpkeys clientkeys

ui.o: ui.c ui.h

sslnonblock.o: vendor/ssl-nonblock.h vendor/ssl-nonblock.c
	cc -g $(CFLAGS) -c -o sslnonblock.o vendor/ssl-nonblock.c

crypto.o: crypto.h crypto.c
	cc -g $(CFLAGS) -c -o crypto.o crypto.c

workerapi.o: workerapi.h workerapi.c prot_client.c
	cc -g $(CFLAGS) -c -o workerapi.o workerapi.c

protc.o: prot_client.c prot_client.h
	cc -g $(CFLAGS) -c -o protc.o prot_client.c

client.o: client.c api.h ui.h util.h

api.o: api.c api.h

db.o: db.c db.h errcodes.h api.h

server.o: server.c util.h db.h errcodes.h api.o keys-server

util.o: util.c util.h

worker.o: worker.c util.h worker.h errcodes.h db.h workerapi.h

client: sslnonblock.o client.o api.o ui.o util.o crypto.o

server: sslnonblock.o server.o api.o util.o worker.o db.o workerapi.o protc.o

keys-server: keys-ttp
	python3 ttp.py server

keys-ttp:
	python3 ttp.py ttp
