#include <string.h>

#include "prot_http.h"
#include "../../common/api.h"
#include "../webserver/route.h"
#include "../webserver/httputil.h"
#include "../../../vendor/ssl-nonblock.h"

#include <openssl/ssl.h>

www_route* routes = NULL;

static int post_to_http(const char* body, struct api_state* state){
    return 1;
}

void protht_init(){
    if(routes == NULL){
        routes = www_route_init("/", "www/index.html");
        www_route_initadd(routes, "/login", "www/login.html");
        www_route_post_initadd(routes, "/login", post_to_http);
    }
}


int protht_notify(struct worker_state* n){
    return 0;
}

int protht_send(struct api_state* state, struct api_msg* msg){
    return 1;
}

int protht_recv(struct api_state* state, struct api_msg* msg){
    // Read message
    char buf[2048];
    int len;

    msg->type = NONE;

    len = ssl_block_read(state->ssl, state->fd, buf, sizeof(buf));

    if(len <= 0) return -1;

    // Parse header
    const char* method = strtok(buf, " ");
    const char* path = strtok(NULL, " ");

    printf("[web] Request %s: %s\n", method, path);

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

        char* body = strtok(NULL, "\n\n");
        body = strtok(NULL, "\n\n");

        printf("Post body %s\n", body);

        int res = cb(body, state);

        return res;
    }

    send404(state->ssl, state->fd);
    return 1;
}