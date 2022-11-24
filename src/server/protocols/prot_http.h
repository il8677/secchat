#ifndef PROT_HTTP_H
#define PROT_HTTP_H

struct api_state;
struct worker_state;
struct api_msg;

void protht_init();

int protht_notify(struct worker_state*);
int protht_send(struct api_state* state, struct api_msg* msg);
int protht_recv(struct api_state* state, struct api_msg* msg);

#endif