// Protocol Callbacks for HTTP client

#ifndef PROT_HTTP_H
#define PROT_HTTP_H

struct worker_state;
struct api_msg;

/// @brief Initialize the webserver
void protht_init();

int protht_send(struct worker_state* state, struct api_msg* msg);
int protht_recv(struct worker_state* state, struct api_msg* msg);

#endif