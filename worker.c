#include "worker.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "db.h"
#include "errcodes.h"
#include "util.h"

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd; /* server <-> worker bidirectional notification channel */
  int server_eof;

  int uid;  // Potential attack surface

  struct db_state dbConn;
};

#define LOGIF(x, y, ...)if(y<0) printf(x, __VA_ARGS__);

static int msg_query_cb(struct api_state* state, struct api_msg* msg){
  return api_send(state, msg) == 1 ? 0 : -1;
}

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state* state) {
  /* TODO implement the function */
  db_get_messages(&state->dbConn, &state->api, state->uid, msg_query_cb);

  return 0;
};

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
static int notify_workers(struct worker_state* state) {
  char buf = 0;
  ssize_t r;

  /* we only need to send something to notify the other workers,
   * data does not matter
   */
  r = write(state->server_fd, &buf, sizeof(buf));
  if (r < 0 && errno != EPIPE) {
    perror("error: write of server_fd failed");
    return -1;
  }
  return 0;
}

/// @brief Verifies the authenticity of a request
/// @param state worker state
/// @param msg request
/// @return 1 if OK, <0 if error
static int authenticate_request(struct worker_state* state,
                                struct api_msg* msg) {
  if (0) return ERR_AUTHENTICATION;

  return 1;
}

/// @brief Checks if a string has a null byte
/// @param str the string to check
/// @param len the length of a string
/// @return 1 if so, 0 otherwise
static int check_null_byte(const char* str, uint32_t len) {
  int hasNullByte = 0;
  for (int i = len - 1; i >= 0; i++) {
    if (str[i] == '\0') {
      hasNullByte = 1;
      break;
    }
  }

  return hasNullByte;
}

/// @brief Checks if the client is logged in
/// @param state worker state
/// @return 1 if logged in, 0 otherwise
static int is_logged_in(struct worker_state* state) { return state->uid == -1; }

/// @brief Verifies the integrity of a request
/// @param state worker state
/// @param msg request
/// @return 1 if OK, <0 if error
static int verify_request(struct worker_state* state, struct api_msg* msg) {
  int res;

  if (!(res = authenticate_request(state, msg))) return res;

  // Type check
  switch (msg->type) {
    case PRIV_MSG:
      if (!check_null_byte(msg->priv_msg.to, MAX_USER_LEN))
        return ERR_INVALID_API_MSG;
    case PUB_MSG:
      if (!check_null_byte(msg->priv_msg.msg, MAX_MSG_LEN))
        return ERR_INVALID_API_MSG;

    case LOGIN:
    case REG:
      if (!check_null_byte(msg->reg.username, MAX_USER_LEN))
        return ERR_INVALID_API_MSG;
      if (!check_null_byte(msg->reg.password, MAX_USER_LEN))
        return ERR_INVALID_API_MSG;
      break;

    case EXIT:
    case WHO:
      break;

    case ERR:     // Client cannot send err!
    case STATUS:  // Client cannot send status!
    default:
      return ERR_INVALID_API_MSG;
      break;
  }

  // User must be logged in unless they're trying to exit or login
  if (msg->type != LOGIN && msg->type != EXIT) {
    if (!is_logged_in(state)) return ERR_NO_USER;
  }

  return 1;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 * @returns       <0 if error
 */
static int execute_request(struct worker_state* state,
                           const struct api_msg* msg) {
  int res = 0;
  int doResponse = 0;

  struct api_msg responseData;

  switch (msg->type) {
    case PRIV_MSG:
    case PUB_MSG:
      db_add_message(&state->dbConn, msg, state->uid);
      notify_workers(state);
      break;
    case WHO:
      // TODO: Who command
      break;
    case LOGIN:
      res = db_login(&state->dbConn, msg);

      if(res >= 0){
        state->uid = res;
        responseData.type = STATUS;
        strcpy(responseData.status.statusmsg, "Login successful");

        doResponse = 1;
      } 
        

      break;
    
    case REG: 
      res = db_register(&state->dbConn, msg);

      if(res >= 0){ 
        state->uid = res;

        responseData.type = STATUS;
        strcpy(responseData.status.statusmsg, "Registration successful");
        
        doResponse = 1;
      }
    break; 

    case EXIT:
      state->uid = -1;
      state->eof = 1;
    break;
    default:
      break;
  }

  LOGIF("[execute_request] error: %d\n", res, res);

  if (doResponse) {
    api_send(&state->api, &responseData);
  }

  return res;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state* state) {
  struct api_msg msg;
  int r, errcode = 0;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    printf("server receive eof\n");
    state->eof = 1;
    return 0;
  }

  /* execute request */
  if ((errcode = verify_request(state, &msg)) == 1) {
    errcode = execute_request(state, &msg);
  }

  LOGIF("[handle_client_request] error: %d\n", errcode);

  // Send error packet
  if (errcode < 0) {
    struct api_msg responseData;
    responseData.type = ERR;
    responseData.err.errcode = errcode;
    api_send(&state->api, &responseData);
  } 
  /* clean up state associated with the message */
  api_recv_free(&msg);

  return errcode < 0;
}

static int handle_s2w_read(struct worker_state* state) {
  char buf[256];
  ssize_t r;

  /* notification from the server that the workers must notify their clients
   * about new messages; these notifications are idempotent so the number
   * does not actually matter, nor does the data sent over the pipe
   */
  errno = 0;
  r = read(state->server_fd, buf, sizeof(buf));
  if (r < 0) {
    perror("error: read server_fd failed");
    return -1;
  }
  if (r == 0) {
    state->server_eof = 1;
    return 0;
  }

  /* notify our client */
  if (handle_s2w_notification(state) != 0) return -1;

  return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state* state) {
  int fdmax, r, success = 1;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  /* wake on incoming messages from client */
  FD_SET(state->api.fd, &readfds);
  /* wake on incoming server notifications */
  if (!state->server_eof) FD_SET(state->server_fd, &readfds);
  fdmax = max(state->api.fd, state->server_fd);

  /* wait for at least one to become ready */
  r = select(fdmax + 1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds)) {
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : 0;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(struct worker_state* state, int connfd,
                             int server_fd) {
  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd);

  state->uid = -1;

  db_state_init(&(state->dbConn));

  return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(struct worker_state* state) {
  /* TODO any additional worker state cleanup */

  /* clean up API state */
  api_state_free(&state->api);

  db_state_free(&(state->dbConn));

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket to the client
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn)) void worker_start(int connfd, int server_fd) {
  struct worker_state state;
  int success = 1;

  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd) != 0) {
    goto cleanup;
  }
  /* TODO any additional worker initialization */

  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  /* TODO any additional worker cleanup */
  worker_state_free(&state);
  printf("Cleanup %d\n", state.eof);
  exit(success ? 0 : 1);
}
