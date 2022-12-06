#include "websockets.h"

#include <string.h>
#include <arpa/inet.h>
#include <endian.h>

#include "../../common/api.h"
#include "../../util/crypto.h"
#include "../../../vendor/ssl-nonblock.h"

#define MAX_HEADER_SIZE 14


// Calculate websockets magic string
// I dont know who designed this process, but web sockets requires a transformation of a key to be certain that webscokets are supported
// Network protocols seem to be real hacked together sometimes...
char* protwb_processKey(const char *str){
    const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const uint16_t concatLen = strlen(str) + strlen(magic);

    // Concatanate the magic with the string
    char* buffer = malloc(concatLen + 1);
    sprintf(buffer, "%s%s", str, magic);

    // Hash and b64
    uint8_t hashResult[SHA_DIGEST_LENGTH];
    char* b64result;

    crypto_hash(buffer, concatLen, hashResult);
    Base64Encode(hashResult, SHA_DIGEST_LENGTH, &b64result);

    free(buffer);

    return b64result;
}

int send_header(struct api_state* state, uint64_t length, char opcode){
    uint8_t header[MAX_HEADER_SIZE];
    uint8_t headerLen = 0;
    memset(header, 0, MAX_HEADER_SIZE);

    header[headerLen++] = opcode | 0x80; // Opcode and fin

    // Fill in length
    uint8_t len1;
    headerLen += 1;
    if(length <= 125) len1 = length;
    else if (length <= UINT32_MAX) {
        len1 = 126;
        *(uint16_t*)(header+2) = htons((uint16_t)length);
        headerLen += 2;
    }
    else {
        len1 = 127;
        *(uint64_t*)(header+2) = htobe32((uint64_t)length);
        headerLen += 8;
    }

    header[1] = len1;
    
    return ssl_block_write(state->ssl, state->fd, header, headerLen);
}