#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H
#include <openssl/ssl.h>

struct api_msg;

//TODO: Return errors
void sendContentHeader(SSL* ssl, int fd, int length);
void send404(SSL* ssl, int fd);
void send400(SSL* ssl, int fd);

char* api_msg_to_json(struct api_msg* msg);

#endif