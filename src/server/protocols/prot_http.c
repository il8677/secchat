#include <string.h>

#include "prot_http.h"
#include "../../common/api.h"
#include "../webserver/route.h"
#include "../webserver/httputil.h"
#include "../../../vendor/ssl-nonblock.h"
#include "../worker/workerapi.h"

#include <openssl/ssl.h>

www_route* routes = NULL;

static int post_to_apimsg(const char* body, unsigned short len, struct api_msg* msg, struct worker_state* state){
    // Copy the body to the msg. Theoretically this copy junk, but the rest of the system will manage safety.
    memset(msg, 0, sizeof(struct api_msg));
    memcpy(msg, body, len);

    return 1;
}

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

static int send_msg(struct api_state* state, struct api_msg* msg){
    char* json = api_msg_to_json(msg);

    char header[13];
    sprintf(header, "%lu\r\n", strlen(json)+1);
    
    // TODO: Error handling
    ssl_block_write(state->ssl, state->fd, header, strlen(header));
    ssl_block_write(state->ssl, state->fd, json, strlen(json));
    ssl_block_write(state->ssl, state->fd, ",\r\n", 3);

    return 0;
}

static int poll_new_messages(const char* body, unsigned short len, struct api_msg* msg, struct worker_state* state){
    // TODO: Check if locking is needed
    static const char header[] = "HTTP/1.1 200 OK\nconnection: keep-alive\ncontent-type: application/json\ntransfer-encoding: chunked\n\n1\r\n[";
    static const char trailer[] = "1\r\n]0\r\n";

    ssl_block_write(state->api.ssl, state->api.fd, header, strlen(header));

    db_get_messages(&state->dbConn, &state->api, state->uid, send_msg, &state->lastviewed);

    ssl_block_write(state->api.ssl, state->api.fd, trailer, strlen(trailer));

    return 1; // TODO: Error handling
}

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

int handle_post(struct worker_state* wstate, char* buf, struct api_msg* msg, const char* path, int len){
    struct api_state* state = &wstate->api;

    post_cb_t cb = www_route_find_post(routes, path);
    if (cb == NULL) {
        send404(state->ssl, state->fd);
        return 1;
    }

    char* remaining = strtok(NULL, "");
    char* body = strstr(remaining, "\r\n\r\n") + 4;

    unsigned short headerLen = body - buf;
    unsigned short bodyLen = len - headerLen;

    if (body == NULL) {
        printf("[web] Error: recieved message could not find a body\n");
        send400(state->ssl, state->fd);

        return 1;
    }

    // Make sure the body could be an api_msg
    if (bodyLen > sizeof(struct api_msg)) {
    printf("[web] Error: Recieved message invalid. len %d expeceted %ld\n\tTotal len: %d headerlen: %d\n",
        bodyLen, sizeof(struct api_msg), len, headerLen);

    send400(state->ssl, state->fd);
    return 1;
    }

    printf("[web: post] recieved api_msg len %u\n", bodyLen);

    return cb(body, bodyLen, msg, wstate);
}

void protht_init(){
    if(routes == NULL){
        routes = www_route_init("/", "www/index.html");
        www_route_post_initadd(routes, "/poll", poll_new_messages);
        www_route_post_initadd(routes, "/postMessage", post_to_apimsg);
        www_route_initadd(routes, "/login.js", "www/login.js");
        www_route_initadd(routes, "/chat.js", "www/chat.js");
        www_route_initadd(routes, "/style.css", "www/style.css");
        www_route_initadd(routes, "/api.js", "www/api.js");
    }
}

int protht_notify(struct worker_state* n){
    return 0;
}

int protht_send(struct worker_state* wstate, struct api_msg* msg){
    struct api_state* state = &wstate->api;

    static const char header[] = "HTTP/1.1 200 OK\nconnection: keep-alive\ncontent-type: application/json\ncontent-length: %ld\n\n";

    char formatted[sizeof(header) + 5]; // TODO: use httputil
    char* msgjson = api_msg_to_json(msg);

    sprintf(formatted, header, strlen(msgjson));

    ssl_block_write(state->ssl, state->fd, formatted, strlen(formatted));
    ssl_block_write(state->ssl, state->fd, msgjson, strlen(msgjson));

    free(msgjson);

    return 1;
}

int protht_recv(struct worker_state* wstate, struct api_msg* msg){
    struct api_state* state = &wstate->api;

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
        return handle_get(state, path);
    }else if(strcmp(method, "POST") == 0){
        return handle_post(wstate, buf, msg, path, len);
    }

    send404(state->ssl, state->fd);
    return 1;
}