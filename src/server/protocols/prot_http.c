#include <string.h>

#include "prot_http.h"
#include "../../common/api.h"
#include "../webserver/route.h"
#include "../webserver/httputil.h"
#include "../../../vendor/ssl-nonblock.h"
#include "../worker/workerapi.h"
#include "prot_websockets.h"

#include <openssl/ssl.h>

www_route* routes = NULL;

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
}
*/

int handle_get(struct api_state* state, const char* path) {
    char* contents = www_route_find(routes, path);
    if (contents == NULL) {
        send404(state->ssl, state->fd);
        return 1;
    }
    // Serve webpage
    sendContentHeader(state->ssl, state->fd, strlen(contents));
    int res = ssl_block_write(state->ssl, state->fd, contents, strlen(contents));
    if (res <= 0) return -1;
    else return 1;
}

void protht_init(){
    if(routes == NULL){
        routes = www_route_init("/", "www/index.html");
        www_route_initadd(routes, "/login.js", "www/login.js");
        www_route_initadd(routes, "/chat.js", "www/chat.js");
        www_route_initadd(routes, "/style.css", "www/style.css");
        www_route_initadd(routes, "/api.js", "www/api.js");
    }
}

int protht_notify(struct worker_state* n){ // HTTP should never notify
    return 0;
}

int protht_send(struct worker_state* wstate, struct api_msg* msg){ // HTTP should never send
    return 1;
}

int protht_recv(struct worker_state* wstate, struct api_msg* msg){
    struct api_state* state = &wstate->api;
    msg->type = NONE; // There is no message interpreted, it is just an HTTP request

    // Read message
    char buf[2048];
    int len;
    memset(buf, 0, 2048);


    len = ssl_block_read(state->ssl, state->fd, buf, sizeof(buf)-1); // Always leave null byte

    if(len <= 0) return -1;

    // Parse header
    const char* method = strtok(buf, " ");
    const char* path = strtok(NULL, " ");

    printf("[web] Request len %d %s: %s\n", len, method, path);

    char* websocket_code = strstr(strtok(NULL, ""), "Sec-WebSocket-Key: ");
    
    // Upgrade to websocket
    // TODO: Verify websocket request validity
    if(websocket_code != NULL){ // TODO: Error checking
        printf("[websocket] Upgrading to websocket\n");
        // Move to the actual code
        websocket_code += strlen("Sec-WebSocket-Key: ");

        // Null terminate the code
        strstr(websocket_code, "\r\n")[0] = '\0';

        char* code = protwb_processKey(websocket_code);

        // Send handshake
        static const char* header = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
        printf("[b64] %.*s  %ld\n", 28, code, strlen(code));
        ssl_block_write(state->ssl, state->fd, header, strlen(header));
        ssl_block_write(state->ssl, state->fd, code, 28); // 20 bytes encoded = 28 bytes
        ssl_block_write(state->ssl, state->fd, "\r\n\r\n", 4);

        // Promote to websocket workerapi (Which can actually handle the app)
        wstate->apifuncs.recv = protwb_recv;
        wstate->apifuncs.send = protwb_send;
        wstate->apifuncs.handle_notification = protwb_notify;

        // Clean up
        free(code);

        return 1;
    }
    else if(strcmp(method, "GET") == 0){
        return handle_get(state, path);
    }

    send404(state->ssl, state->fd);
    return 1;
}