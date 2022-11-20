#ifndef API_CALLBACKS_H
#define API_CALLBACKS_H

struct worker_state;
struct api_state;
struct api_msg;

typedef int (*api_notify_t)(struct worker_state*);
typedef int (*api_send_t)(struct api_state*, struct api_msg*);
typedef int (*api_recv_t)(struct api_state*, struct api_msg*);

// Function pointers to protocol api
struct api_callbacks{
  api_notify_t handle_notification;
  api_send_t send;
  api_recv_t recv;
};

#endif