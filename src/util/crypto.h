#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#include <openssl/ssl.h>

void hash(char* data, uint32_t len, unsigned char* output);
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text);

#endif