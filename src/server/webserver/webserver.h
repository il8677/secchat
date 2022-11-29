// A light weight "copy" of the worker just to serve web content
// This code is quite messy, since it reuses a lot of the worker, 
// but architecturally, I didnt want every web request to create a full worker

struct server_state;

void webserver_init();
int web_start(int connfd);