// Protocol callbacks for websocket client

#ifndef PROT_WEBSOCKETS_H
#define PROT_WEBSOCKETS_H

struct worker_state;
struct api_msg;

int protwb_send(struct worker_state* state, struct api_msg* msg);
int protwb_recv(struct worker_state* state, struct api_msg* msg);

#endif