#ifndef _API_H_
#define _API_H_

#include <stdint.h>

#define MAX_USER_LEN 16
#define MAX_MSG_LEN 160

// Because preprocessors cannot do athrithmetic 
#define MAX_USER_LEN_M1 15
#define MAX_MSG_LEN_M1 159

enum msg_type_t { ERR, STATUS, PRIV_MSG, PUB_MSG, WHO, LOGIN, REG, EXIT };

typedef signed long timestamp_t;

/// @brief The struct of data to be sent over the wire
struct api_msg {
  // TODO: Auth info

  enum msg_type_t type;

  char errcode;
  
  union {
    struct {
      char statusmsg[MAX_MSG_LEN];
    } status;

    struct {
      timestamp_t timestamp;

      char msg[MAX_MSG_LEN];

      char from[MAX_USER_LEN];
      char to[MAX_USER_LEN];
    } priv_msg;

    struct {
      timestamp_t timestamp;

      char msg[MAX_MSG_LEN];

      char from[MAX_USER_LEN];
    } pub_msg;

    struct {
      char users[MAX_MSG_LEN];
    } who;

    struct {
      char username[MAX_USER_LEN];
      char password[MAX_USER_LEN];  // TODO: Make hash
    } login;

    struct {
      char username[MAX_USER_LEN];
      char password[MAX_USER_LEN];  // TODO: Make hash
    } reg;

    struct {
    } exit;
  };
};

struct api_state {
  /// @brief File descriptor of socket
  int fd;
  /* TODO add required fields */
};

int api_recv(struct api_state* state, struct api_msg* msg);
void api_recv_free(struct api_msg* msg);
int api_send(struct api_state* state, struct api_msg* msg);

void api_state_free(struct api_state* state);
void api_state_init(struct api_state* state, int fd);

/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
