#include "crypto.h"
#include "../common/api.h"

#include <stdlib.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>

// TODO: Use salt
// https://www.openssl.org/docs/man1.1.1/man3/SHA512_Init.html
void crypto_hash(char* data, uint32_t len, unsigned char* output){
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(output, &ctx);
}

int read_file(const char* path, char** out){
    // TODO: Error handling
    FILE* f = fopen(path, "r");
    fseek(f, 0, SEEK_END);
    int fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    *out = malloc(fsize+1);
    fread(*out, fsize, 1, f);
    (*out)[fsize] = '\0';

    return 0; 
}

static uint8_t* makeBuffer(const char* str, size_t len){
    uint8_t* buf = malloc(len);
    memset(buf, 0, len);
    memcpy(buf, str, strlen(str));

    return buf;
}

// This function is a mess, but it encrypts the input using the users password
char* crypto_aes_encrypt(char* bytes, uint16_t byteslen, const char* password, char encrypt, uint16_t* outLen){
    *outLen = 0;

    // 16 bytes / block, round up to find number of blocks, * 16 for final byttes;
    int outputLen = (byteslen/16 + 1)*16;
    char* output = malloc(outputLen);    

    memset(output, 0, outputLen);
    
    const EVP_CIPHER* type = EVP_aes_128_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // TODO: Use salt as iv
    uint8_t* key = makeBuffer(password, EVP_CIPHER_key_length(type));
    uint8_t* iv = makeBuffer(password, EVP_CIPHER_iv_length(type));

    EVP_CipherInit(ctx, type, key, iv, encrypt);
    EVP_CipherUpdate(ctx, (unsigned char*)output, &outputLen, (unsigned char*)bytes, byteslen);
    *outLen += outputLen;
    EVP_CipherFinal(ctx, (unsigned char*)output+outputLen, &outputLen);
    *outLen += outputLen;

    free(key);
    free(iv);
    EVP_CIPHER_CTX_free(ctx);

    return output;
}

void crypto_get_user_auth(const char* name, const char* password, char** outPrivkey, char** outCert){
    // Go get info from the TTP
    char command[1024] = "python3 ttp.py -c ";
    strcat(command, name);
    system(command);

    // Read the info
    read_file("clientkeys/cert.pem", outCert);
    read_file("clientkeys/priv.pem", outPrivkey);
}

// Taken from the provided examples
X509* crypto_parse_x509_string(const char* x509str){
    BIO* bio = BIO_new_mem_buf(x509str, strlen(x509str));

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return cert;
}

RSA* crypto_parse_RSA_priv_string(const char* rsapriv){
    BIO* bio = BIO_new_mem_buf(rsapriv, strlen(rsapriv));

    RSA* key = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    return key;
}

// Adapted from https://stackoverflow.com/questions/73631293/how-to-encrypt-a-string-using-openssl-c-library-and-a-public-key-file
void crypto_RSA_pubkey_encrypt(char* dst, X509* key, char* msg, uint16_t msglen){
    // Get public key from certificate
    EVP_PKEY* pkey = X509_get_pubkey(key);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    
    size_t outlen = MAX_ENCRYPT_LEN;

    EVP_PKEY_encrypt(ctx, (unsigned char*)dst, &outlen, (unsigned char*)msg,  msglen);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

char* crypto_RSA_privkey_decrypt(RSA* key, const char* msg){
    char* outbuf = malloc(RSA_size(key));
    
    // Note: This is depractated but it was provided in the examples
    RSA_private_decrypt(RSA_size(key), (const unsigned char*) msg, (unsigned char*) outbuf, key, RSA_PKCS1_OAEP_PADDING);

    // Worse comes to worse we just print junk
    outbuf[RSA_size(key)] = '\0';

    return outbuf;
}