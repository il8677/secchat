#include <string.h>

#include "prot_http.h"
#include "../../common/api.h"
#include "../webserver/route.h"
#include "../webserver/httputil.h"
#include "../../../vendor/ssl-nonblock.h"
#include "../worker/workerapi.h"

#include <openssl/ssl.h>


/*
static char* api_msg_to_json(struct api_msg* msg){
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
            sprintf(json, "{\"type\": %d, \"timestamp\": %ld, \"msg\":\"%s\", from:\"%s\", to:\"%s\"}", 
            msg->type, msg->priv_msg.timestamp, msg->priv_msg.msg, msg->priv_msg.from, msg->priv_msg.to);
            break;
        case PUB_MSG:
            sprintf(json, "{\"type\": %d, \"timestamp\": %ld, \"msg\":\"%s\", from:\"%s\"}", 
            msg->type, msg->pub_msg.timestamp, msg->pub_msg.msg, msg->pub_msg.from);
            break;
        case WHO:
            sprintf(json, "{\"type\": %d, \"who\": \"%s\"}", msg->type, msg->who.users);
            break;

        default:
            sprintf(json, "{\"type\": %d}", NONE);
        }

    return json;
}*/

int protht_notify(struct worker_state* n){
    return 0;
}

int protht_send(struct worker_state* wstate, struct api_msg* msg){
    return 1;
}

int protht_recv(struct worker_state* wstate, struct api_msg* msg){
    return 1;
}