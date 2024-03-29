#include <string.h>

#include "httputil.h"

#include <openssl/ssl.h>

#include "../../common/api.h"
#include "../../util/crypto.h"
#include "../../../vendor/ssl-nonblock.h"

void sendContentHeader(SSL* ssl, int fd, int length){
    // This used to be keep-alive, but it stopped working and firefox kept requesting things on seperate connections randomly, so now we close 
    static const char header[] = "HTTP/1.1 200 OK\nconnection: close\ncontent-length: %d\n\n";

    char formatted[sizeof(header)+10];

    sprintf(formatted, header, length);

    ssl_block_write(ssl, fd, formatted, strlen(formatted));
}

void send404(SSL* ssl, int fd){
    static const char err404[] = "HTTP/1.1 404 Not Found\nconnection: keep-alive\ncontent-length: 0\n\n"; 

    ssl_block_write(ssl, fd, err404, sizeof(err404));
}

void send400(SSL* ssl, int fd){
    static const char err404[] = "HTTP/1.1 400 Not Found\nconnection: keep-alive\ncontent-length: 0\n\n"; 

    ssl_block_write(ssl, fd, err404, sizeof(err404));
}

/// @brief Converts an api_msg to json format, encodes encrypted fields in b64
/// @return A dynamically allocated address where the json string is
// messy function, but I dont know if its possible to do formatting functions in a clean way
char* api_msg_to_json(struct api_msg* msg){
    char* priv = NULL;    
    unsigned int jsonLoc = 0; // Keep track of where in the buffer we have written to

    if (msg->encPrivKeyLen){
        // B64 encode
        Base64Encode((unsigned char*)msg->encPrivKey, msg->encPrivKeyLen, &priv);
    }

    // json overhead space + additional data
    int allocatedSize = 75 + (msg->encPrivKeyLen? strlen(priv) : 0) + msg->certLen;

    char* json;
    
    // Main message
    switch(msg->type){
        case ERR:
            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d, \"errcode\": %d", msg->type, msg->errcode);
            break;
        case STATUS:
            allocatedSize += sizeof(msg->status.statusmsg);
            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d, \"status\": \"%s\"", msg->type, msg->status.statusmsg);
            break;
        case PRIV_MSG:{
            // This inefficient, because we're copying a lot of buffers instead of just writing a buffer once, but it's good enough

            // b64 encrypted fields
            char* frommssg; // We dont need tomsg since server->client messages only contain this one field
            char* signature;

            Base64Encode((unsigned char*)msg->priv_msg.signature, MAX_ENCRYPT_LEN, &signature);
            Base64Encode((unsigned char*)msg->priv_msg.frommsg, MAX_ENCRYPT_LEN, &frommssg);

            // Subtract from the size needed since we have b64 encoded strings instead of the messages & signature
            allocatedSize += strlen(frommssg) + strlen(signature) + sizeof(msg->priv_msg) - MAX_ENCRYPT_LEN * 2;

            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d, \"signature\": \"%s\", \
            \"timestamp\": %ld, \"msg\": \"%s\", \"from\":\"%s\", \"to\":\"%s\"", 
            msg->type, signature, msg->priv_msg.timestamp, frommssg, msg->priv_msg.from, msg->priv_msg.to);
            
            free(frommssg);
            free(signature);
            break;}
        case PUB_MSG:{
            char* signature;
            char* msgb64; // We need to base64 encode the message since it might contain special characters that escape JSON

            Base64Encode((unsigned char*)msg->pub_msg.signature, MAX_ENCRYPT_LEN, &signature);
            Base64Encode((unsigned char*)msg->pub_msg.msg, strnlen(msg->pub_msg.msg, MAX_MSG_LEN_M1), &msgb64);

            // Subtrack from the size needed since we have the b64 string instead of the signature
            allocatedSize += strlen(signature) + strlen(msgb64) + sizeof(msg->pub_msg) - MAX_ENCRYPT_LEN - MAX_MSG_LEN;
            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d, \"signature\": \"%s\", \"timestamp\": %ld, \"msg\":\"%s\", \"from\":\"%s\"", 
            msg->type, signature, msg->pub_msg.timestamp, msgb64, msg->pub_msg.from);

            free(signature);
            free(msgb64);
            break;}
        case WHO:
            allocatedSize += sizeof(msg->who);
            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d, \"who\": \"%s\"", msg->type, msg->who.users);
            break;

        case LOGINACK:
            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d", msg->type);
            break;
        case KEY:
            json = malloc(allocatedSize);
            jsonLoc += sprintf(json, "{\"type\": %d", msg->type);
            break;

        default:
            json = malloc(allocatedSize);
            sprintf(json, "{\"type\": %d", NONE);
            goto cleanup;
    }

    // Attach extra data
    if(msg->encPrivKeyLen){
        jsonLoc += sprintf(json + jsonLoc, ", \"privkey\": \"%s\"", priv);
    }

    if(msg->certLen){
        jsonLoc += sprintf(json + jsonLoc, ", \"cert\": \"%s\"", msg->cert);
    }

    sprintf(json + jsonLoc, "}");

    cleanup:
    free(priv);

    return json;
}