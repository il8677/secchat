#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <err.h>
#include <ctype.h>

#include "../common/api.h"
#include "ui.h"
#include "../util/util.h"
#include "../common/errcodes.h"
#include "../../vendor/ssl-nonblock.h"

#include <openssl/err.h>
#include <openssl/ssl.h>

struct client_state {
  struct api_state api;
  int eof;
  struct ui_state ui;
};

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state* state,
  const char* hostname, uint16_t port) {
  int fd;
  struct sockaddr_in addr;

  assert(state);
  assert(hostname);

  /* look up hostname */
  if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("error: cannot allocate server socket");
    return -1;
  }

  /* connect to server */
  if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
    perror("error: cannot connect to server");
    close(fd);
    return -1;
  }

  return fd;
}

static int client_process_command(struct client_state* state) {

  assert(state);  

  char *input = read_input(16);

  if(input == NULL) return -1; // STDIN Closed

  struct api_msg apimsg;
  int errcode = 0;

  //remove whitespace at the start of the input 
  char *p = input;
  char *p_end = input + strlen(input);
  while (p < p_end && isspace(*p)) p++;
  
  if (p[0] == '@') errcode = input_handle_privmsg(&apimsg, p);
  else if (p[0] == '/') {                      
    p++;
    if (strlen(p) == 0 || p[0] == ' ') errcode = ERR_COMMAND_ERROR;
    else {
      char* cmd = strtok(p, " ");
      if (strcmp(cmd, "exit") == 0) { errcode = input_handle_exit(&apimsg, p); state->eof = 1;}
      else if (strcmp(cmd, "users") == 0) errcode = input_handle_users(&apimsg, p);
      else if (strcmp(cmd, "login") == 0) errcode = input_handle_login(&apimsg, p);
      else if (strcmp(cmd, "register") == 0) errcode = input_handle_register(&apimsg, p);
      else errcode = ERR_COMMAND_ERROR;
    }
  }
  else errcode = input_handle_pubmsg(&apimsg, p);
  
  if (errcode == ERR_COMMAND_ERROR){
    printf("error: unknown command %s\n", input);
    free(input);
    return 0;
  }
  
  free(input);
  if (errcode != 0) {
    printf("error: invalid command format\n\t");
    switch (errcode) {
      case ERR_NAME_INVALID:     printf("Given name is invalid.\n"); break;
      case ERR_MESSAGE_INVALID:  printf("Given message is invalid\n"); break;
      case ERR_MESSAGE_TOOLONG:  printf("Given message is too long, max number of characters: %d.\n", MAX_MSG_LEN); break;
      case ERR_PASSWORD_INVALID: printf("Given password is invalid.\n"); break;
      case ERR_USERNAME_TOOLONG: printf("Given username is too long, max number of characters: %d.\n", MAX_USER_LEN); break;
      case ERR_PASSWORD_TOOLONG: printf("Given password is too long, max number of characters: %d.\n", MAX_USER_LEN); break;
      case ERR_INVALID_NR_ARGS:  printf("Invalid number of arguments given.\n"); break;
    }
    return 0; //CAN BE CHANGED to errcode but for testing this was annoying
  }

  api_send(&(state->api), &apimsg);
  return 0;
}
  

static void error(const struct api_msg *msg){
  switch (msg->errcode)
  {
  case ERR_SQL:
    printf("Internal sql error, please try again.\n");
    break;
  case ERR_NAME_INVALID:
    printf("Client name unvalid, please try again\n");
    break;
  case ERR_INVALID_API_MSG:
    printf("Internal server error, please try again\n");  
    break;
  case ERR_USERNAME_EXISTS:
    printf("error: user %s already exists\n", msg->login.username);
    break;
  case ERR_INCORRECT_LOGIN:
    printf("error: invalid credentials\n");
    break;
  case ERR_AUTHENTICATION:
    printf("Authentication error, please try again.\n");
    break;
  case ERR_LOGGED_IN:
  case ERR_NO_USER:
    printf("error: command not currently available\n");
    break;      
  case ERR_RECIPIENT_INVALID:
    printf("error: user not found\n");
    break;
  default:
    printf("unknown error %d, please try again.\n", msg->errcode);
    break;
  }
}
static void status(const struct api_msg * msg){
  printf("%.*s\n",MAX_MSG_LEN, msg->status.statusmsg);
}

static void formatTime(char* buffer, int size, timestamp_t timestamp){
  struct tm* tm_info;
  tm_info = localtime(&timestamp);

  strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

static void privMsg(const struct api_msg * msg){
  char buffer[26];
  formatTime(buffer, 26, msg->priv_msg.timestamp);
  
  //never print more than the respective maximum lengths.
  printf("%s %.*s: @%.*s %.*s\n", buffer, MAX_USER_LEN, 
  msg->priv_msg.from, MAX_USER_LEN, msg->priv_msg.to, MAX_MSG_LEN, msg->priv_msg.msg);
}

static void pubMsg(const struct api_msg * msg){
  char buffer[26];
  formatTime(buffer, 26, msg->priv_msg.timestamp);

  //never print more than the respective maximum lengths.
  printf("%s %s: %s\n", buffer,
  msg->pub_msg.from, msg->pub_msg.msg);
}
static void who(const struct api_msg * msg){
  printf("users:\n%s\n", msg->who.users);
}
static void key(const struct api_msg * msg){
  //verify the certificate 
  //place key in list
  //look at the queue
}
/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
  struct client_state* state,
  const struct api_msg* msg) {
    assert(state);
    switch (msg->type)
    {
    case ERR:
    error(msg);
      break;
    case STATUS:
      status(msg);
      break;
    case PRIV_MSG:
      privMsg(msg);
      break;
    case PUB_MSG:
      pubMsg(msg);
      break;
    case WHO:
      who(msg);
      break;
    case KEY:
      key(msg);  
    default:
      printf("Some error happened %d\n", msg->type);
      break;
    }

  return 0;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state* state) {
  struct api_msg msg;
  int r, success = 1;

  assert(state);

  /* wait for incoming request, set eof if there are no more requests */
  r = api_recv(&state->api, &msg);
  if (r < 0) return -1;
  if (r == 0) {
    printf("client receive eof\n");
    state->eof = 1;
    return 0;
  }

  //printf("[handle_server_request] incoming packet %d\n", msg.type);

  /* execute request */
  if (execute_request(state, &msg) != 0) {
    success = 0;
  }

  /* clean up state associated with the message */
  api_recv_free(&msg);
  return success ? 0 : -1;
}

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state* state) {
  int fdmax, r;
  fd_set readfds;

  assert(state);

  /* list file descriptors to wait for */
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);
  FD_SET(state->api.fd, &readfds);
  fdmax = state->api.fd;

  /* wait for at least one to become ready */
  r = select(fdmax+1, &readfds, NULL, NULL, NULL);
  if (r < 0) {
    if (errno == EINTR) return 0;
    perror("error: select failed");
    return -1;
  }

  /* handle ready file descriptors */
  if (FD_ISSET(STDIN_FILENO, &readfds)) {
    return client_process_command(state);
  }
  if (FD_ISSET(state->api.fd, &readfds)) {
    if(!ssl_has_data(state->api.ssl)) return 0;
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state* state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);


  return 0;
}

static void client_state_free(struct client_state* state) {

  /* cleanup API state */
  api_state_free(&state->api);

  /* cleanup UI state */
  ui_state_free(&state->ui);

}

static void usage(void) {
  printf("usage:\n");
  printf("  client host port\n");
  exit(1);
}

int main(int argc, char **argv) {
  int fd;
  uint16_t port;
  struct client_state state;


  /* check arguments */
  if (argc != 3) usage();
  if (parse_port(argv[2], &port) != 0) usage();

  /* preparations */
  client_state_init(&state);

  /* connect to server */
  fd = client_connect(&state, argv[1], port);
  if (fd < 0) return 1;

  /* initialize API */
  api_state_init(&state.api, fd, TLS_client_method());
  // verify server certificate
  SSL_CTX_load_verify_locations(state.api.ctx, "ttpkeys/ca-cert.pem", NULL);
  SSL_set_verify(state.api.ssl, SSL_VERIFY_PEER, NULL);
  set_nonblock(fd);

  int res;
  // SSL handshake
  if((res = ssl_block_connect(state.api.ssl, state.api.fd)) != 1){
    printf("Fatal error %d\n", res=SSL_get_error(state.api.ssl, res));
    
    if(res == SSL_ERROR_SSL){
        printf("\t(%s)\n", ERR_error_string(ERR_get_error(), NULL));
    }
    
    return 1;
  }

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);

  client_state_free(&state);
  close(fd);

  return 0;
}
