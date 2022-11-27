#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H
#include <openssl/ssl.h>

//TODO: Return errors
void sendContentHeader(SSL* ssl, int fd, int length);
void send404(SSL* ssl, int fd);
void send400(SSL* ssl, int fd);

#endif