#ifndef HTTP_UTIL_H
#define HTTP_UTIL_H
#include <openssl/ssl.h>

struct api_msg;

/// @brief Sends an HTTP header for content
/// @param length The length of the content
void sendContentHeader(SSL* ssl, int fd, int length);

void send404(SSL* ssl, int fd);
void send400(SSL* ssl, int fd);

/// @brief Converts an api_msg to json
/// @return A dynamically allocated string with the json in it
char* api_msg_to_json(struct api_msg* msg);

#endif