.PHONY: all clean

CFLAGS=-g -Wall -Werror -UDEBUG
LDLIBS=-lsqlite3 -lcrypto -lssl
LDFLAGS=-fsanitize=address

all: client server

# TODO: fix this mess

clean:
	rm -f server client *.o *.db*
	rm -rf serverkeys ttpkeys clientkeys

ui.o: src/client/ui.c src/client/ui.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

sslnonblock.o: vendor/ssl-nonblock.c vendor/ssl-nonblock.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

crypto.o: src/util/crypto.c
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

workerapi.o: src/server/worker/workerapi.c src/server/worker/workerapi.h src/server/protocols/prot_client.c
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

protc.o: src/server/protocols/prot_client.c src/server/protocols/prot_client.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

client.o: src/client/client.c src/common/api.h src/client/ui.h src/util/util.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

api.o: src/common/api.c src/common/api.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

route.o: src/server/webserver/route.c src/server/webserver/route.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

httputil.o: src/server/webserver/httputil.c src/server/webserver/httputil.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

protht.o: src/server/protocols/prot_http.c src/server/protocols/prot_http.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

db.o: src/server/db.c src/server/db.h src/common/api.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

server.o: src/server/server.c src/util/util.h src/server/db.h api.o keys-server
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

util.o: src/util/util.c src/util/util.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

worker.o: src/server/worker/worker.c src/util/util.h src/server/worker/worker.h src/server/db.h src/server/worker/workerapi.h
	$(CC) $(CFLAGS) $(LDLIBS) -c -o $@ $<

client: sslnonblock.o client.o api.o ui.o util.o crypto.o

server: sslnonblock.o server.o api.o util.o worker.o db.o workerapi.o protc.o protht.o route.o httputil.o

keys-server: keys-ttp
	python3 ttp.py server

keys-ttp:
	python3 ttp.py ttp
