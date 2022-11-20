#include "crypto.h"

// TODO: Use sha-2 and salt
// https://www.openssl.org/docs/man1.1.1/man3/SHA512_Init.html
void hash(char* data, uint32_t len, unsigned char* output){
    SHA_CTX ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, len);
    SHA1_Final(output, &ctx);
}