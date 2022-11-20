#include <string.h>

#include "httputil.h"

#include <openssl/ssl.h>
#include "../../../vendor/ssl-nonblock.h"

void sendContentHeader(SSL* ssl, int fd, int length){
    static const char header[] = "HTTP/1.1 200 OK\nconnection: keep-alive\ncontent-length: %d\n\n";

    char formatted[sizeof(header)+5];

    sprintf(formatted, header, length);

    ssl_block_write(ssl, fd, formatted, strlen(formatted));
}

void send404(SSL* ssl, int fd){
    static const char err404[] = "HTTP/1.1 404 Not Found\nconnection: keep-alive\ncontent-length: 0\n\n"; 

    ssl_block_write(ssl, fd, err404, sizeof(err404));
}