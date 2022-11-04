#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "api.h"
#include "ui.h"
#include "util.h"

struct client_state {
  struct api_state api;
  int eof;
  struct ui_state ui;
  /* TODO client state variables go here */
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

  /* TODO read and handle user command from stdin;
   * set state->eof if there is no more input (read returns zero)
   */

  char *input;
  int c;
  size_t len = 0;
  size_t size = 16;
  input = malloc(size);
  while (EOF != (c = fgetc(stdin)) && c != '\n') {
    input[len++] = c;
    if (len == size) {
      input = realloc(input, sizeof(*input)*(size+=16));
    }
  }
  input[len++] = '\0';
  input = realloc(input, sizeof(*input)*size);

  //check for too long message
  if (strlen(input) > MAX_MSG_LEN) { 
    printf("Message too long, max character amount: %d.\n", MAX_MSG_LEN);
    free(input);
    return 0;
  } else {
    struct api_msg apimsg;
    
    //remove whitespace before msg
    char *p = input;
    char *p_end = input + strlen(input);
    while (p < p_end && isspace(*p)) p++;
    if (p[0] == '@') {                                  //private msg
      p++;
      char *to = strtok(p, " ");
      char *msg = strtok(NULL, "");
      
      apimsg.type = PRIV_MSG;
      strcpy(apimsg.priv_msg.to, to);
      strcpy(apimsg.priv_msg.msg, msg);
      //scrcpy(apimsg.priv_msg.from, state->ui.from) ?? where to get the from name from :)
      //api_send(&(state->api), &apimsg);
    } else if (p[0] == '/') {                           //commands:
      p++;
      if (strcmp(p, "exit") == 0) {                     //exit
        apimsg.type = EXIT;
        state->eof = 1;
        //api_send(&(state->api), &apimsg); ?? do we need to send the msg_api with an exit also?
      }
      else if (strcmp(p, "users") == 0) {               //users
        apimsg.type = WHO;
        //api_send(&(state->api), &apimsg);
      }
      else {           
        char *cmd = strtok(p, " ");
        if (strcmp(cmd, "login") == 0) {                //login
          char *username = strtok(NULL, " ");
          char *password = strtok(NULL, " ");

          apimsg.type = LOGIN;
          strcpy(apimsg.login.username, username);
          strcpy(apimsg.login.password, password);
          //api_send(&(state->api), &apimsg);
          
        } else if (strcmp(cmd, "register") == 0) {      //register
          char *username = strtok(NULL, " ");
          char *password = strtok(NULL, " ");

          apimsg.type = REG;
          strcpy(apimsg.reg.username, username);
          strcpy(apimsg.reg.password, password);
          //api_send(&(state->api), &apimsg);

        } else {
          printf("Command not recognised.\n");
        }
      }
    } else {                                          //public message
      apimsg.type = PUB_MSG;
      strcpy(apimsg.pub_msg.msg, p);
      //scrcpy(apimsg.pub_msg.from, state->from) ?? same question as with the priv msg, where to get username from
      //api_send(&(state->api), &apimsg);

    }
  }
  free(input);
  return 0;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(
  struct client_state* state,
  const struct api_msg* msg) {

  /* TODO handle request and reply to client */

  return -1;
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
    state->eof = 1;
    return 0;
  }

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

  /* TODO if we have work queued up, this might be a good time to do it */

  /* TODO ask user for input if needed */

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
  /* TODO once you implement encryption you may need to call ssl_has_data
   * here due to buffering (see ssl-nonblock example)
   */
  if (FD_ISSET(state->api.fd, &readfds)) {
    return handle_server_request(state);
  }
  return 0;
}

static int client_state_init(struct client_state* state) {
  /* clear state, invalidate file descriptors */
  memset(state, 0, sizeof(*state));

  /* initialize UI */
  ui_state_init(&state->ui);

  /* TODO any additional client state initialization */

  return 0;
}

static void client_state_free(struct client_state* state) {

  /* TODO any additional client state cleanup */

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
  api_state_init(&state.api, fd);

  /* TODO any additional client initialization */

  /* client things */
  while (!state.eof && handle_incoming(&state) == 0);

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}
