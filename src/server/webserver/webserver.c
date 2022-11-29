#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>

#include "../worker/workerapi.h" // borrow some functionality
#include "route.h" 
#include "httputil.h" 
#include "../../../vendor/ssl-nonblock.h" 

www_route* routes = NULL;

void webserver_init(){
    if(routes == NULL){
        routes = www_route_init("/", "www/index.html");
        www_route_initadd(routes, "/login.js", "www/login.js");
        www_route_initadd(routes, "/chat.js", "www/chat.js");
        www_route_initadd(routes, "/style.css", "www/style.css");
        www_route_initadd(routes, "/api.js", "www/api.js");
    }
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

int web_start(int connfd){
    struct api_state api;
    int res;

    worker_api_init(&api, connfd);

    printf("[web] Handshaking\n");
    if((res = SSL_accept(api.ssl)) != 1){
        printf("[web] Fatal error %d\n", res=SSL_get_error(api.ssl, res));
        if(res==SSL_ERROR_SSL)
            printf("[web] SSL Error\n");
        exit(res);
    }
    printf("[web] Handshake completed\n");

    set_nonblock(connfd);
    int len;
    char buf[2048];

    memset(buf, 0, 2048);

    while(1){
        len = ssl_block_read(api.ssl, api.fd, buf, sizeof(buf)-1); // Always leave null byte
        if(len <= 0) break;

        // Parse header
        const char* method = strtok(buf, " ");
        const char* path = strtok(NULL, " ");

        printf("[web] Request len %d %s: %s\n", len, method, path);

        if(strcmp(method, "GET") == 0){
            handle_get(&api, path);
        }else{
            send404(api.ssl, api.fd);
        }
    }

    exit(res);
}