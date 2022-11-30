#include <string.h>
#include <openssl/ssl.h>
#include "../../util/crypto.h"

// I dont know who designed this process, but web sockets requires a transformation of a key to be certain that webscokets are supported
// Network protocols seem to be real hacked together sometimes...
char* protwb_processKey(const char *str){
    const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const uint16_t concatLen = strlen(str) + strlen(magic);

    // Concatanate the magic with the string
    char* buffer = malloc(concatLen + 1);
    sprintf("%s%s", str, magic);

    // Hash and b64
    char* hashResult[SHA_DIGEST_LENGTH];
    char* b64result;

    hash(buffer, concatLen, hash);
    Base64Encode(hashResult, SHA_DIGEST_LENGTH, &b64result);

    free(buffer);

    return b64result;
}