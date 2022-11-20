#ifndef PROT_HTTP_H
#define PROT_HTTP_H

int protht_notify(struct worker_state*);
int protht_send(struct worker_state* state, struct api_msg* msg);
int protht_recv(struct worker_state* state, struct api_msg* msg);

#endif