#include <string.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <endian.h>

#include "../worker/workerapi.h"
#include "../../../vendor/ssl-nonblock.h"
#include "../../util/crypto.h"

int sendFrame(struct api_state* state, uint8_t* payload, uint64_t length, char opcode){
    char* data = malloc(length + 10);
    memset(data, 0, length + 10);
    data[0] = opcode | 0x8; // opcode and fin

    char* payloadLoc = data + 2;

    uint8_t len1;

    if(length <= 125) len1 = length;
    else if (length <= UINT32_MAX) {
        len1 = 126;
        *(uint32_t*)(data+2) = (uint32_t)length;
        payloadLoc += 4;
    }
    else {
        len1 = 127;
        *(uint64_t*)(data+2) = (uint64_t)length;
        payloadLoc += 8;
    }

    data[1] = len1;

    memcpy(payloadLoc, payload, length);

    // TODO: More elegant / safe way to calculate length
    int res = ssl_block_write(state->ssl, state->fd, data, payloadLoc + length - data);

    free(data);

    return res > 0 ? 0 : -1;
}

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
    msg->type = NONE; // There might not be a message

    uint8_t buf[8196];
    int len;
    memset(buf, 0, 2048);

    len = ssl_block_read(state->ssl, state->fd, buf, sizeof(buf)-1); // Always leave null byte

    if(len <= 0) return -1;

    // Get header values
    uint8_t fin = buf[0] >> 7;
    uint8_t opcode = buf[0] & 0x0f;
    uint8_t mask = buf[1] >> 7;
    uint8_t len1 = buf[1] & 0x7F;

    uint64_t payloadLen = len1;

    uint8_t* data = buf+2;

    if(!fin){
        printf("[websockets] Error, recieved continuation bit, not supported!\n");
        return -1;
    }

    // Read the appropriate length
    if(len1 == 126){
        payloadLen = htons(*(uint16_t*)data);
        data += 2;
    }else if (len1 == 127){
        payloadLen = be64toh(*(uint64_t*)data);
        data += 8;
    }

    if(payloadLen > sizeof(buf) - (data - buf) - mask * 4){
        printf("[websockets] Error, payload is too big\n");
        return -1;
    }

    printf("Payload %ld\n", payloadLen);

    // Unmask data
    if(mask){
        uint8_t* maskData = data;
        data += 4;

        for(uint64_t i = 0; i < payloadLen; i++){
            data[i] ^= maskData[i%4];
        }
    }else{
        printf("[websockets] Recieved unmasked message, the RFC tells me to exit\n");
        return -1;
    }

    // Dispatch data
    switch (opcode)
    {
    case 0x9: // Ping
        return sendFrame(state, data, payloadLen, 0xA);
        break;
    case 0x2:
        // Check if data is correct size
        if(payloadLen > sizeof(struct api_msg)){
            printf("[websockets] Error, recieved data is too large");
            return -1;
        }
        memcpy(msg, data, payloadLen);
        return 1;
        break;
    default:
        printf("[websockets] Unsupported opcode %x\n", opcode);
        return -1;
        break;
    }

    return 1;    
}