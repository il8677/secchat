#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#include <openssl/ssl.h>

void crypto_hash(char* data, uint32_t len, unsigned char* output);

char* crypto_aes_encrypt(char* bytes, uint16_t bytesLen, const char* password, char encrypt, uint16_t* outLen);

/// @brief Asks the TTP to generate a certificate and private key for user
/// @param name The name of the user
/// @param outPrivKey The place to put the encrypted PEM of the private key
/// @param outCert The place to put the PEM of the cert
void crypto_get_user_auth(const char* name, const char* password, char** outPrivKey, char** outCert);

/// @brief Parses string to produce X509 cert
X509* crypto_parse_x509_string(const char* x509str);

/// @brief Parses string to produce RSA privkey
RSA* crypto_parse_RSA_priv_string(const char* rsapriv);

/// @brief RSA encrypts a message using an X509 certificate as key
void crypto_RSA_pubkey_encrypt(char* dst, X509* key, char* msg, uint16_t msglen);

char* crypto_RSA_privkey_decrypt(RSA* key, const char* msg);

void crypto_RSA_sign(RSA* key, const char* msg, uint16_t msglen, unsigned char* output);

int crypto_RSA_verify(X509* key, unsigned char* msg, uint16_t msglen, char* hashmsg, uint16_t hashmsglen);

#endif