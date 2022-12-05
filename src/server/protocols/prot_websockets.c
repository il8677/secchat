#include <string.h>
#include <openssl/ssl.h>
#include <arpa/inet.h>
#include <endian.h>

#include "../worker/workerapi.h"
#include "../webserver/httputil.h"
#include "../../../vendor/ssl-nonblock.h"
#include "../../util/crypto.h"

#define MAX_HEADER_SIZE 14

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
    
    printf("Writing header len %d\n", headerLen);
    for(int i = 0; i < headerLen; i++){
        printf("%x ", header[i]);
    }
    printf("\n");
    return ssl_block_write(state->ssl, state->fd, header, headerLen);
}

int send_frame(struct api_state* state, uint8_t* payload, uint64_t length, char opcode){
    int res = send_header(state, length, opcode);

    if(res <= 0) return -1;
    res = ssl_block_write(state->ssl, state->fd, payload, length);

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

    crypto_hash(buffer, concatLen, hashResult);
    Base64Encode(hashResult, SHA_DIGEST_LENGTH, &b64result);

    free(buffer);

    return b64result;
}

int wb_api_to_json_send(struct api_state* state, struct api_msg* msg){
    char* json = api_msg_to_json(msg);
    int res = send_frame(state, (unsigned char*)json, strlen(json), 0x1);
    printf("Sent len %ld json %s\n", strlen(json), json);
    free(json);

    return res == 0;
}

static int msg_query_cb(struct worker_state* state, struct api_msg* msg){
    return wb_api_to_json_send(&state->api , msg) == 1 ? 0 : -1;
}

int protwb_notify(struct worker_state* state){
    db_get_messages(&state->dbConn, state, state->uid, msg_query_cb, &state->lastviewed);
    return 0;
}

int protwb_send(struct worker_state* state, struct api_msg* msg){
    API_PRINT_MSG("[websockets] Sending", (*msg));
    return wb_api_to_json_send(&state->api, msg);
}

int protwb_recv(struct worker_state* wstate, struct api_msg* msg){
    struct api_state* state = &wstate->api;
    msg->type = NONE; // There might not be a message

    uint8_t buf[8196];
    int len;
    memset(buf, 0, 2048);

    len = ssl_block_read(state->ssl, state->fd, buf, sizeof(buf)-1); // Always leave null byte

    if(len <= 0) {
        return -1;
    }
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
        return send_frame(state, data, payloadLen, 0xA);
    case 0x2:
        // Check if data is correct size
        if(payloadLen < sizeof(struct api_msg)){
            printf("[websockets] Error, recieved data is too small\n");
            return -1;
        }
        memcpy(msg, data, sizeof(struct api_msg));
        data += sizeof(struct api_msg);

        // Check if remaining data is of correct size
        if(msg->certLen + msg->encPrivKeyLen != payloadLen - sizeof(struct api_msg)){
            printf("[websockets] Error, additional data doesn't add up\n");
            return -1;
        }
        
        // Additional data
        if(msg->encPrivKeyLen){
            msg->encPrivKey = malloc(msg->encPrivKeyLen);
            memcpy(msg->encPrivKey, data, msg->encPrivKeyLen);
            data += msg->encPrivKeyLen;
        }

        if(msg->certLen){
            msg->cert = malloc(msg->certLen);
            memcpy(msg->cert, data, msg->certLen);
            data += msg->certLen;
        }
        return 1;
    default:
        printf("[websockets] Unsupported opcode %x\n", opcode);
        return -1;
    }

    return 1;    
}