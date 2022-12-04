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

  // User must be logged in unless they're trying to exit or login
  if (msg->type != LOGIN && msg->type != EXIT && msg->type != REG) {
    if (!is_logged_in(state)) return ERR_NO_USER;
  }

  return 1;
}

static int prep_msg_share(struct worker_state* state, struct api_msg* msg){
  // Attach sender cert if it wasn't yet sent
  if(list_add(state->sentCerts, msg->priv_msg.from, NULL, 0, 1) == 0){  
    db_add_cert(&state->dbConn, msg, msg->priv_msg.from);
  }

  return state->apifuncs.send(state, msg) == 1 ? 0 : -1;
}

int notify(struct worker_state* state) {
  if(is_logged_in(state))
    db_get_messages(&state->dbConn, state, state->uid, prep_msg_share, &state->lastviewed);

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

  state->sentCerts = list_init();

  return 0;
}

void worker_state_free(struct worker_state* state) {
  /* clean up API state */
  api_state_free(&state->api);

  db_state_free(&(state->dbConn));

  list_free(state->sentCerts);

  /* close file descriptors */
  close(state->server_fd);
  close(state->api.fd);
}


int handle_client_request(struct worker_state* state) {
  struct api_msg msg;
  api_msg_init(&msg);
  int r, errcode = 0;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = state->apifuncs.recv(state, &msg);
  if (r == -1) {
    printf("server receive eof\n");
    state->eof = 1;
    api_msg_free(&msg);
    return 0;
  }

  API_PRINT_MSG("recv", msg);

  if(msg.type==NONE) {
    api_msg_free(&msg);
    return 0;
  }

  /* execute request */
  if ((errcode = verify_request(state, &msg)) == 1) {
    errcode = execute_request(state, &msg);
  }

  LOGIF("[handle_client_request] error: %d\n", errcode, errcode);

  // Send error packet
  if (errcode < 0) {
    msg.type = ERR;
    msg.errcode = errcode;
    state->apifuncs.send(state, &msg);
  } 
  /* clean up state associated with the message */
  api_msg_free(&msg);

  return errcode < 0;
}

// Spagetti code ahead!
int execute_request(struct worker_state* state,
                           const struct api_msg* msg) {
  int res = 0;
  int doResponse = 0;

  struct api_msg responseData;
  api_msg_init(&responseData);

  switch (msg->type) {
    case KEY:
      res = db_add_cert(&state->dbConn, &responseData, msg->key.who);
      if(res == ERR_NO_USER){
         res = ERR_RECIPIENT_INVALID;
      }else if(res >= 0){
        doResponse = 1;
        responseData.type = KEY;
        memcpy(responseData.key.who, msg->key.who, MAX_USER_LEN);

        list_add(state->sentCerts, msg->key.who, NULL, 0, 1);
      }
      break;
    case PRIV_MSG:
      res = db_add_priv_message(&state->dbConn, msg, state->uid);
      
      if(res >= 0)
        notify_workers(state);
      break;
    case PUB_MSG:
      res = db_add_pub_message(&state->dbConn, msg, state->uid);

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
        responseData.type = LOGINACK;
        strcpy(responseData.status.statusmsg, "authentication succeeded");

        doResponse = 1;

        setUser(state, res, msg->login.username);
        // Add the users key pair to the acknowledgement
        db_add_cert(&state->dbConn, &responseData, msg->login.username);
        db_add_privkey(&state->dbConn, &responseData, msg->login.username);
      } 
      break;
    case REG: 
      if(is_logged_in(state)){
        res = ERR_LOGGED_IN;
        break;
      }

      res = db_register(&state->dbConn, msg);

      if(res >= 0){ 
        responseData.type = LOGINACK;
        strcpy(responseData.status.statusmsg, "registration succeeded");
        
        doResponse = 1;

        setUser(state, res, msg->reg.username);

        // Add the users key pair to the acknowledgement
        db_add_cert(&state->dbConn, &responseData, msg->reg.username);
        db_add_privkey(&state->dbConn, &responseData, msg->reg.username);
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
    API_PRINT_MSG("send", responseData);
    state->apifuncs.send(state, &responseData);
  }

  api_msg_free(&responseData);

  return res;
}
