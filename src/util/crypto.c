#include "crypto.h"

#include <stdlib.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

// TODO: Use sha-2 and salt (do in another function, this function and sha-1 are needed for web)
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

char* crypto_aes_encrypt(char* str, const char* password, char encrypt){
    // 16 bytes / block, round up to find number of blocks, * 16 for final byttes;
    int outputLen = (strlen(str)/16 + 1)*16;
    char* output = malloc(outputLen);
    memset(output, 0, outputLen);
    
    const EVP_CIPHER* type = EVP_aes_128_cbc();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // TODO: Use salt as iv
    uint8_t* key = makeBuffer(password, EVP_CIPHER_key_length(type));
    uint8_t* iv = makeBuffer(password, EVP_CIPHER_iv_length(type));

    EVP_CipherInit(ctx, type, key, iv, encrypt);
    EVP_CipherUpdate(ctx, (unsigned char*)output, &outputLen, (unsigned char*)str, strlen(str));
    EVP_CipherFinal(ctx, (unsigned char*)output, &outputLen);

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

