#ifndef API_CALLBACKS_H
#define API_CALLBACKS_H

struct worker_state;
struct api_state;
struct api_msg;

// Sends an api message to client, returns 1 on success -1 on error
typedef int (*api_send_t)(struct worker_state*, struct api_msg*);

// Recieves an api message from client, returns 1 on success -1 on error. aip_msg.type could be set to NONE meaning no api_msg recieved
typedef int (*api_recv_t)(struct worker_state*, struct api_msg*);

// Function pointers to protocol api
struct api_callbacks{
  api_send_t send;
  api_recv_t recv;
};

#endif