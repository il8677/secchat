#include <assert.h>
#include <string.h>


#include <unistd.h>

#include "api.h"
#include "../../vendor/ssl-nonblock.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state* state, struct api_msg* msg) {

  assert(state);
  assert(msg);

  int res = ssl_block_read(state->ssl, state->fd, msg, sizeof(struct api_msg));

  if(res > 0){
    return 1;
  }else{
    return -1;
  }

  return -1;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg* msg) {

  assert(msg);
}

/// @brief Sends msg over the wire
/// @param state The api state
/// @param msg The API message
/// @return -1 if error, 1 if success

int api_send(struct api_state* state, struct api_msg* msg){
  assert(state);
  assert(msg);

  int res = ssl_block_write(state->ssl, state->fd, msg, sizeof(struct api_msg));

  if(res <= 1) return -1;
  
  return 1;
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state* state) {
  // Clean up SSL
  SSL_free(state->ssl);
  SSL_CTX_free(state->ctx);

  assert(state);
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state* state, int fd, const SSL_METHOD* method) {

  assert(state);

  /* initialize to zero */
  memset(state, 0, sizeof(*state));

  /* store connection socket */
  state->fd = fd;
  
  state->ctx = SSL_CTX_new(method);
  state->ssl = SSL_new(state->ctx);

  SSL_set_fd(state->ssl,  fd);
}
