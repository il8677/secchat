#include "route.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>

struct www_route {
    www_route* next;
    char path[25];
    char method[8];
    int len;
    char contents[];
};

www_route* www_route_init(const char* path, const char* filepath){
    // TODO: File error handling
    // Open file and read length
    FILE* f = fopen(filepath, "r");
    fseek(f, 0, SEEK_END);
    int fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    // Create route in shared memory (To avoid duplicating loaded files)
    www_route* route = mmap(NULL, sizeof(www_route) + fsize + 1, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    strncpy(route->path, path, 25);
    strcpy(route->method, "GET");
    route->next = NULL;
    route->len = fread(route->contents, fsize, 1, f);
    
    fclose(f);

    return route;
}

void www_route_initadd(www_route* head, const char* name, const char* path){
    www_route_add(head, www_route_init(name, path));
}

www_route* www_route_post_init(const char* path, post_cb_t cb){
    www_route* route = mmap(NULL, sizeof(www_route) + sizeof(post_cb_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    strncpy(route->path, path, 25);
    strcpy(route->method, "POST");

    route->next = NULL;
    route->len = sizeof(www_route);

    // Copy callback to contents
    memcpy(route->contents, &cb, sizeof(post_cb_t));

    return route;
}

void www_route_post_initadd(www_route* head, const char* path, post_cb_t cb){
    www_route_add(head, www_route_post_init(path, cb));
}


void www_route_free(www_route* head){
    if(head->next == NULL) return;
    www_route_free(head->next);

    munmap(head, sizeof(www_route) + head->len);
}

void www_route_add(www_route* head, www_route* newRoute){
    while(head->next != NULL) head = head->next;

    head->next = newRoute;
}

static www_route* www_route_objectfind(www_route* head, const char* path, const char* method){
    while(head != NULL){
        if(strcmp(head->path, path) == 0 && strcmp(head->method, method)) return head;
        head = head->next;
    } 

    return NULL;
}

char* www_route_find(www_route* head, const char* path){
    www_route* route = www_route_objectfind(head, path, "GET");

    char* contents = route == NULL ? NULL : route->contents;

    return contents;
}

post_cb_t www_route_find_post(www_route* head, const char* path){
    www_route* route = www_route_objectfind(head, path, "POST");

    post_cb_t cb = route == NULL ? NULL : (post_cb_t)route->contents;

    return cb;
}