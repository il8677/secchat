#include <string.h>

#include "httputil.h"

#include <openssl/ssl.h>

#include "../../common/api.h"
#include "../../../vendor/ssl-nonblock.h"

void sendContentHeader(SSL* ssl, int fd, int length){
    static const char header[] = "HTTP/1.1 200 OK\nconnection: keep-alive\ncontent-length: %d\n\n";

    char formatted[sizeof(header)+5]; // TODO: do this better

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

char* api_msg_to_json(struct api_msg* msg){
    // TODO: find a better way to be sure to allocate enough space for the json string
    char* json = malloc(50 + 10 + 10 + MAX_MSG_LEN + MAX_USER_LEN + MAX_USER_LEN);
    
    switch(msg->type){
        case ERR:
            sprintf(json, "{\"type\": %d, \"errcode\": %d}", msg->type, msg->errcode);
            break;
        case STATUS:
            sprintf(json, "{\"type\": %d, \"status\": \"%s\"}", msg->type, msg->status.statusmsg);
            break;
        case PRIV_MSG:
            //sprintf(json, "{\"type\": %d, \"timestamp\": %ld, \"msg\":\"%s\", \"from\":\"%s\", \"to\":\"%s\"}", 
            //msg->type, msg->priv_msg.timestamp, msg->priv_msg.msg, msg->priv_msg.from, msg->priv_msg.to);
            break;
        case PUB_MSG:
            sprintf(json, "{\"type\": %d, \"timestamp\": %ld, \"msg\":\"%s\", \"from\":\"%s\"}", 
            msg->type, msg->pub_msg.timestamp, msg->pub_msg.msg, msg->pub_msg.from);
            break;
        case WHO:
            sprintf(json, "{\"type\": %d, \"who\": \"%s\"}", msg->type, msg->who.users);
            break;

        default:
            sprintf(json, "{\"type\": %d}", NONE);
        }

    return json;
}