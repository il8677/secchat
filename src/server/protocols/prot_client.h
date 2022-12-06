// Protocol Callbacks for native client

#ifndef PROT_CLIENT_H
#define PROT_CLIENT_H

struct worker_state;
struct api_msg;

int protc_send(struct worker_state* state, struct api_msg* msg);
int protc_recv(struct worker_state* state, struct api_msg* msg);

#endif