#include <errno.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "workerapi.h"
#include "../../common/errcodes.h"

#define LOGIF(x, y, ...)if(y<0) printf(x, __VA_ARGS__);

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
static int is_logged_in(struct worker_state* state) { return state->uid != -1; }

/// @brief Verifies the authenticity of a request
/// @param state worker state
/// @param msg request
/// @return 1 if OK, <0 if error
static int authenticate_request(struct worker_state* state,
                                struct api_msg* msg) {
  if (0) return ERR_AUTHENTICATION;

  return 1;
}

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
      // We dont use from so we dont need to check it
    case LOGIN:
    case REG:
      if (!check_null_byte(msg->reg.username, MAX_USER_LEN))
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
  if (msg->type != LOGIN && msg->type != EXIT && msg->type != REG) {
    if (!is_logged_in(state)) return ERR_NO_USER;
  }

  return 1;
}


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

static void setUser(struct worker_state* state, int uid, const char* username){
    state->uid = uid;

    // Copy to shared memory
    strncpy(state->names+MAX_USER_LEN*state->index, username, MAX_USER_LEN);
    // Reset lastviewed
    state->lastviewed = 0;

    // Give user unread messages
    notify_workers(state);
}

int worker_state_init(struct worker_state* state, int connfd,
                             int server_fd, char* name, int index, struct api_callbacks callbacks) {
  /* initialize */
  memset(state, 0, sizeof(*state));
  state->server_fd = server_fd;

  /* set up API state */
  api_state_init(&state->api, connfd, TLS_server_method());

  state->uid = -1;

  db_state_init(&(state->dbConn));

  state->names = name;
  state->index = index;

  state->apifuncs = callbacks;

  SSL_use_certificate_file(state->api.ssl, "serverkeys/cert.pem", SSL_FILETYPE_PEM);
  SSL_use_PrivateKey_file(state->api.ssl, "serverkeys/priv.pem", SSL_FILETYPE_PEM);

  return 0;
}

void worker_state_free(struct worker_state* state) {
  /* clean up API state */
  api_state_free(&state->api);

  db_state_free(&(state->dbConn));


  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}


int handle_client_request(struct worker_state* state) {
  struct api_msg msg;
  int r, errcode = 0;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = state->apifuncs.recv(&state->api, &msg);
  if (r == -1) {
    printf("server receive eof\n");
    state->eof = 1;
    return 0;
  }

  if(msg.type==NONE) return 0;

  /* execute request */
  if ((errcode = verify_request(state, &msg)) == 1) {
    errcode = execute_request(state, &msg);
  }

  LOGIF("[handle_client_request] error: %d\n", errcode, errcode);

  // Send error packet
  if (errcode < 0) {
    msg.type = ERR;
    msg.errcode = errcode;
    state->apifuncs.send(&state->api, &msg);
  } 
  /* clean up state associated with the message */
  api_recv_free(&msg);

  return errcode < 0;
}

// Spagetti code ahead!
int execute_request(struct worker_state* state,
                           const struct api_msg* msg) {
  int res = 0;
  int doResponse = 0;

  struct api_msg responseData;

  switch (msg->type) {
    case PRIV_MSG:
    case PUB_MSG:
      res = db_add_message(&state->dbConn, msg, state->uid);

      if(res >= 0)
        notify_workers(state);
      break;
    case WHO:
    {
      responseData.type = WHO;
      char* membuffer = responseData.who.users;
      int next = 0;

      for(int i = 0; i < MAX_CONNECTIONS*MAX_USER_LEN; i += MAX_USER_LEN){
        char* currentName = state->names + i;
        
        if(currentName[0] == '\0') continue;

        strcpy(membuffer+next, currentName);
        next += strlen(currentName);
        // Replace null byte with new line
        membuffer[next++] = '\n';
      }
      // Add nullbyte to the end
      if(next) membuffer[next-1] = '\0';

      doResponse = 1;
      break;
    }
    case LOGIN:
      if(is_logged_in(state)){
        res = ERR_LOGGED_IN;
        break;
      }

      res = db_login(&state->dbConn, msg);

      if(res >= 0){
        responseData.type = STATUS;
        strcpy(responseData.status.statusmsg, "authentication succeeded");

        doResponse = 1;

        setUser(state, res, msg->login.username);
      } 
      break;
    case REG: 
      if(is_logged_in(state)){
        res = ERR_LOGGED_IN;
        break;
      }

      res = db_register(&state->dbConn, msg);

      if(res >= 0){ 
        responseData.type = STATUS;
        strcpy(responseData.status.statusmsg, "registration succeeded");
        
        doResponse = 1;

        setUser(state, res, msg->reg.username);
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
    state->apifuncs.send(&state->api, &responseData);
  }

  return res;
}
