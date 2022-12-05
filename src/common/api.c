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

  if(res <= 0) return -1;

  msg->encPrivKey = NULL;
  msg->cert = NULL;

  // Recieve additional data
  if(msg->encPrivKeyLen){
    msg->encPrivKey = malloc(msg->encPrivKeyLen);
    res = ssl_block_read(state->ssl, state->fd, msg->encPrivKey, msg->encPrivKeyLen);
    if(res <= 0) return -1;
    if(res != msg->encPrivKeyLen) return -1; // Recieved wrong length, malformed packet = drop peer
  }

  if(msg->certLen){
    msg->cert = malloc(msg->certLen);
    res = ssl_block_read(state->ssl, state->fd, msg->cert, msg->certLen);
    if(res <= 0) return -1;
    if(res != msg->certLen) return -1; // Recieved wrong length, malformed packet = drop peer
    
    // Null terminate so we can treat as string safely
    msg->cert[msg->certLen-1] = '\0';
  }
  return 1;
}

void api_msg_init(struct api_msg* msg){
  memset(msg, 0, sizeof(struct api_msg));
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_msg_free(struct api_msg* msg) {

  assert(msg);

  if(msg->encPrivKey) free(msg->encPrivKey);
  if(msg->cert) free(msg->cert);
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

  // Send additional data
  if(msg->encPrivKeyLen){
    res = ssl_block_write(state->ssl, state->fd, msg->encPrivKey, msg->encPrivKeyLen);
    if(res <= 1) return -1;
  }
  
  // Send additional data
  if(msg->certLen){
    res = ssl_block_write(state->ssl, state->fd, msg->cert, msg->certLen);
    if(res <= 1) return -1;
  } 

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

void api_null_terminate(struct api_msg* msg){
  switch (msg->type)
  {
  case STATUS:
    msg->status.statusmsg[MAX_MSG_LEN-1] = '\0';
  break;
  case PRIV_MSG:
    msg->priv_msg.from[MAX_USER_LEN-1] = '\0';
    msg->priv_msg.to[MAX_USER_LEN-1] = '\0';
  break;
  case PUB_MSG:
    msg->pub_msg.from[MAX_USER_LEN-1] = '\0';
    msg->pub_msg.msg[MAX_MSG_LEN-1] = '\0';
  break;
  case WHO:
    msg->who.users[MAX_MSG_LEN-1] = '\0';
  break;
  case KEY:
    msg->key.who[MAX_USER_LEN-1] = '\0';
  break;
  case REG:
  case LOGIN:
    msg->reg.username[MAX_USER_LEN-1] = '\0';
  break;
  default:
    break;
  }
}