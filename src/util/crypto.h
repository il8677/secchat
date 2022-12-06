#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>

#include <openssl/ssl.h>

#define TTP_PATH "clientkeys/ca.cert"

/// @brief Encodes data to B64
/// @param buffer The string
/// @param length The length of the data
/// @param b64text The uninitialized pointer that will contain the output
int Base64Encode(const unsigned char* buffer, size_t length, char** b64text);

/// @brief Hashes using SHA-1
/// @param data The data to hash
/// @param len The length of the data
/// @param output The buffer to output to
void crypto_hash(const char* data, uint32_t len, unsigned char* output);

/// @brief Hashes using SHA-2 (256)
/// @param data The data to hash
/// @param len The length of the data
/// @param output The buffer to output to
void crypto_sha2_hash(const char* data, uint32_t len, const char* salt, unsigned char* output);

/// @brief AES encrpyts / dececrypts
/// @param bytes The bytes to encrypt/decrpyt
/// @param bytesLen The length of the bytes
/// @param password The key
/// @param iv The initialization vector
/// @param encrypt 1 for encrypt, 0 for decrypt
/// @param outLen The place to store the output length
/// @return A dynamically allocated buffer containing the output data
char* crypto_aes_encrypt(char* bytes, uint16_t bytesLen, const char* password, const char* iv, char encrypt, uint16_t* outLen);

/// @brief Asks the TTP to generate a certificate and private key for user
/// @param name The name of the user
/// @param outPrivKey The place to put the encrypted PEM of the private key
/// @param outCert The place to put the PEM of the cert
void crypto_get_user_auth(const char* name, char** outPrivKey, char** outCert);

/// @brief Parses string to produce X509 cert
X509* crypto_parse_x509_string(const char* x509str);

/// @brief Parses string to produce RSA privkey
RSA* crypto_parse_RSA_priv_string(const char* rsapriv);

/// @brief RSA encrypts a message using an X509 certificate as key
void crypto_RSA_pubkey_encrypt(char* dst, X509* key, char* msg, uint16_t msglen);

/// @brief Decrypts a RSA public key encrypted message
char* crypto_RSA_privkey_decrypt(RSA* key, const char* msg);

/// @brief Produces a signature for a message
/// @param key Private key
/// @param msg The message to sign
/// @param msglen The length of the message
/// @param output The place to put the signature
void crypto_RSA_sign(RSA* key, const char* msg, uint16_t msglen, unsigned char* output);

/// @brief Verifies a signature
/// @param key X509 cert with the signers public key
/// @return If the signature matches
int crypto_RSA_verify(X509* key, const char* msg, uint16_t msglen, const char* signature, uint16_t signaturelen);

/// @brief Verifies if a X509 certificate was signed by the CA and if the name matches
/// @return If the cert was valid
int crypto_verify_x509(X509* target, const char* name);

#endif