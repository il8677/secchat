#ifndef SERVERAPI_H
#define SERVERAPI_H

#include "../../common/api.h"
#include "../apicallbacks.h"
#include "../db.h"

struct worker_state {
  struct api_state api;
  int eof;
  int server_fd; /* server <-> worker bidirectional notification channel */
  int server_eof;

  char* names; // Shared mem with server
  int index;

  int uid;  // Potential attack surface
  timestamp_t lastviewed;

  struct db_state dbConn;

  struct api_callbacks apifuncs;
};

/// @brief Initializes a worker_api for the server
void worker_api_init(struct api_state* state, int connfd);

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 * @param name         pointer to shared memory for name
 */
int worker_state_init(struct worker_state* state, int connfd, int server_fd, char* name, int index, struct api_callbacks callbacks);

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
void worker_state_free(struct worker_state* state);

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
int handle_client_request(struct worker_state* state);

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 * @returns       <0 if error
 */
int execute_request(struct worker_state* state, const struct api_msg* msg);

#endif