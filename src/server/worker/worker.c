// Responsible for setting up a worker, basically just does a handshake, loops over select, and calls the worker api to handle incoming stuff

#include "worker.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>

#include "../../util/util.h"
#include "../../../vendor/ssl-nonblock.h"
#include "workerapi.h"

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
  if (notify(state) != 0) return -1;

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

  if (FD_ISSET(state->api.fd, &readfds)) {
    if(!ssl_has_data(state->api.ssl)) return 0;
    if (handle_client_request(state) != 0) success = 0;
  }
  if (FD_ISSET(state->server_fd, &readfds)) {
    if (handle_s2w_read(state) != 0) success = 0;
  }
  return success ? 0 : 0;
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
__attribute__((noreturn)) void worker_start(int connfd, int server_fd, char* sharedmem, int index, struct api_callbacks callbacks) {
  struct worker_state state;
  int success = 1;
  printf("worker-Start\n");
  /* initialize worker state */
  if (worker_state_init(&state, connfd, server_fd, sharedmem, index, callbacks) != 0) {
    goto cleanup;
  }

  int res;
  printf("Waiting for SSL handshake\n");
  // SSL handshake
  if((res = SSL_accept(state.api.ssl)) != 1){
    printf("Fatal error %d\n", res=SSL_get_error(state.api.ssl, res));
    if(res==SSL_ERROR_SSL)
        printf("\t(%s)\n", ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }
  set_nonblock(connfd);

  printf("Handshake completed\n");

  /* handle for incoming requests */
  while (!state.eof) {
    if (handle_incoming(&state) != 0) {
      success = 0;
      break;
    }
  }

cleanup:
  /* cleanup worker */
  worker_state_free(&state);
  printf("Cleanup %d\n", state.eof);
  exit(success ? 0 : 1);
}
