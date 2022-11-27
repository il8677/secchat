#include <string.h>

#include "prot_http.h"
#include "../../common/api.h"
#include "../webserver/route.h"
#include "../webserver/httputil.h"
#include "../../../vendor/ssl-nonblock.h"

#include <openssl/ssl.h>

www_route* routes = NULL;

static int post_to_apimsg(const char* body, struct api_msg* msg, unsigned short len){
    // Copy the body to the msg. Theoretically this copy junk, but the rest of the system will manage safety.
    memset(msg, 0, sizeof(struct api_msg));
    memcpy(msg, body, len);

    return 1;
}

void protht_init(){
    if(routes == NULL){
        routes = www_route_init("/", "www/index.html");
        www_route_initadd(routes, "/login", "www/login.html");
        www_route_post_initadd(routes, "/login", post_to_apimsg);
        www_route_initadd(routes, "/api.js", "www/api.js");
    }
}


int protht_notify(struct worker_state* n){
    return 0;
}

int protht_send(struct api_state* state, struct api_msg* msg){ // protht cannot send, so do
    return 1;
}

int protht_recv(struct api_state* state, struct api_msg* msg){
    // Read message
    char buf[2048];
    int len;
    memset(buf, 0, 2048);

    msg->type = NONE;

    len = ssl_block_read(state->ssl, state->fd, buf, sizeof(buf)-1); // Always leave null byte

    if(len <= 0) return -1;

    printf("\n");

    // Parse header
    const char* method = strtok(buf, " ");
    const char* path = strtok(NULL, " ");

    printf("[web] Request len %d %s: %s\n", len, method, path);

    if(strcmp(method, "GET") == 0){
        char* contents = www_route_find(routes, path);
        if(contents == NULL){
            send404(state->ssl, state->fd);
            return 1;
        }
        // Serve webpage
        sendContentHeader(state->ssl, state->fd, strlen(contents));
        int res = ssl_block_write(state->ssl, state->fd, contents, strlen(contents));
        if(res <= 0) return -1;
        else return 1;
    }else if(strcmp(method, "POST") == 0){
        post_cb_t cb = www_route_find_post(routes, path);
        if(cb == NULL){
            send404(state->ssl, state->fd);
            return 1;
        }
        
        char* remaining = strtok(NULL, "");
        char* body = strstr(remaining, "\r\n\r\n")+4;

        unsigned short headerLen = body - buf;
        unsigned short bodyLen = len - headerLen;

        if(body == NULL){
            printf("[web] Error: recieved message could not find a body\n");
            send400(state->ssl, state->fd);

            return 1;
        }

        // Make sure the body could be an api_msg
        if(bodyLen > sizeof(struct api_msg)){
            printf("[web] Error: Recieved message invalid. len %d expeceted %ld\n\tTotal len: %d headerlen: %d\n", bodyLen, sizeof(struct api_msg), len, headerLen);

            send400(state->ssl, state->fd);
            return 1;
        }

        printf("[web: post] recieved api_msg len %u\n", bodyLen);

        return cb(body, msg, bodyLen);
    }

    send404(state->ssl, state->fd);
    return 1;
}