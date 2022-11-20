#ifndef ROUTE_H
#define ROUTE_H

typedef struct www_route www_route;

www_route* www_route_init(const char* name, const char* path);
void www_route_initadd(www_route* head, const char* name, const char* path);
void www_route_free(www_route* head);
char* www_route_find(www_route* head, const char* path);
void www_route_add(www_route* head, www_route* newRoute);
char* www_route_find(www_route* head, const char* path);
#endif