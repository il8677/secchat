#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#include <openssl/ssl.h>

void crypto_hash(char* data, uint32_t len, unsigned char* output);

char* crypto_aes_encrypt(char* str, const char* password, char encrypt);

/// @brief Asks the TTP to generate a certificate and private key for user
/// @param name The name of the user
/// @param outPrivKey The place to put the encrypted PEM of the private key
/// @param outCert The place to put the PEM of the cert
void crypto_get_user_auth(const char* name, const char* password, char** outPrivKey, char** outCert);

#endif