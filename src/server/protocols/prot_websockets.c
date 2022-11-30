#include <string.h>
#include <openssl/ssl.h>

#include "../worker/workerapi.h"
#include "../../../vendor/ssl-nonblock.h"
#include "../../util/crypto.h"

// I dont know who designed this process, but web sockets requires a transformation of a key to be certain that webscokets are supported
// Network protocols seem to be real hacked together sometimes...
char* protwb_processKey(const char *str){
    const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const uint16_t concatLen = strlen(str) + strlen(magic);

    // Concatanate the magic with the string
    char* buffer = malloc(concatLen + 1);
    sprintf(buffer, "%s%s", str, magic);

    // Hash and b64
    unsigned char hashResult[SHA_DIGEST_LENGTH];
    char* b64result;

    hash(buffer, concatLen, hashResult);
    Base64Encode(hashResult, SHA_DIGEST_LENGTH, &b64result);

    free(buffer);

    return b64result;
}

int protwb_notify(struct worker_state* state){
    return 0;
}

int protwb_send(struct worker_state* state, struct api_msg* msg){
    return 1;
}

int protwb_recv(struct worker_state* wstate, struct api_msg* msg){
    struct api_state* state = &wstate->api;
    char buf[2048];
    int len;
    memset(buf, 0, 2048);


    len = ssl_block_read(state->ssl, state->fd, buf, sizeof(buf)-1); // Always leave null byte

    printf("[websockets] %d: %s\n", len, (char*)buf);

    return 1;    
}