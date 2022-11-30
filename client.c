#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <err.h>

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

  char *input = read_input(16);
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
  
  if (errcode != 0) {
    switch (errcode) {
    case ERR_COMMAND_ERROR:    printf("--Command not recognised.\n"); break;
    case ERR_NAME_INVALID:     printf("--Given name is invalid.\n"); break;
    case ERR_MESSAGE_INVALID:  printf("--Given message is invalid\n"); break;
    case ERR_MESSAGE_TOOLONG:  printf("--Given message is too long, max number of characters: %d.\n", MAX_MSG_LEN); break;
    case ERR_PASSWORD_INVALID: printf("--Given password is invalid.\n"); break;
    case ERR_USERNAME_TOOLONG: printf("--Given username is too long, max number of characters: %d.\n", MAX_USER_LEN); break;
    case ERR_PASSWORD_TOOLONG: printf("--Given password is too long, max number of characters: %d.\n", MAX_USER_LEN); break;
    case ERR_INVALID_NR_ARGS:  printf("--Invalid number of arguments given.\n"); break;
  }
    free(input);
    return 0; //CAN BE CHANGED to errcode but for testing this was annoying
  } else {
    
    //api_send(&(state->api), &apimsg); //Commented for testing purposes
    free(input);
    return 0;
  }
}
  

static void error(const struct api_msg *msg){
  switch (msg->err.errcode)
  {
  case ERR_SQL:
    printf("internal sql error, please try again.");
    break;
  case -2:
    printf("client name unvalid, please try again");
    break;
  case -3:
    printf("");  
  
  default:
    break;
  }
}
static void status(const struct api_msg * msg){
  printf("%.*s\n",MAX_MSG_LEN, msg->status.statusmsg);
}
static void privMsg(const struct api_msg * msg){
  printf("%s private message from: %.*s, to: %.*s \n %.*s\n", ctime(&msg->priv_msg.timestamp), MAX_USER_LEN,
  msg->priv_msg.from, MAX_USER_LEN, msg->priv_msg.to, MAX_MSG_LEN, msg->priv_msg.msg);
}
static void pubMsg(const struct api_msg * msg){
  printf("%s public message from: %.*s\n %.*s\n", ctime(&msg->priv_msg.timestamp), MAX_USER_LEN,
  msg->priv_msg.from, MAX_MSG_LEN, msg->priv_msg.msg);
}
static void who(const struct api_msg * msg){
  printf("users: %s", msg->who.users);
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
    default:
      printf("Some error happened");
      break;
    }
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

// static X509 *certfromstr(const char *str) {
//   /* this creates an OpenSSL I/O Stream (BIO) to read from a memory buffer */
//   BIO *bio = BIO_new_mem_buf(str, strlen(str));

//   /* parse PEM-formatted certificate from memory I/O stream */
//   X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
//   BIO_free(bio);

//   return cert;
// }

int verify_cert() {
  const char ca_cert_str[] = "./ttpkeys/ca-cert.pem";
  const char server_cert_str[] = "./serverkeys/cert.pem";
  X509 *ca_cert, *server_cert;
  EVP_PKEY *ca_pkey = NULL; 
  EVP_PKEY *server_pkey = NULL;
  int r1, r2;
  
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  BIO *ca_certbio = BIO_new(BIO_s_file());
  BIO *server_certbio = BIO_new(BIO_s_file());
  BIO *outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);
  
  BIO_read_filename(ca_certbio, ca_cert_str);
  BIO_read_filename(server_certbio, server_cert_str);
  
  //loading CA certificate and extra CA pubkey
  if (! (ca_cert = PEM_read_bio_X509(ca_certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading ca_cert into memory\n");
    exit(-1);
  }
  if ((ca_pkey = X509_get_pubkey(ca_cert)) == NULL)
    BIO_printf(outbio, "Error getting public key from CA certificate");

  //verify CA, but idk if this is necessary
  r1 = X509_verify(ca_cert, ca_pkey);
  printf("certificate is %scorrectly signed by CA\n", (r1 == 1) ? "" : "not ");

  //loading server sertificate and server pubkey
  if (! (server_cert = PEM_read_bio_X509(server_certbio, NULL, 0, NULL))) {
    BIO_printf(outbio, "Error loading server_cert into memory\n");
    exit(-1);
  }
  if ((server_pkey = X509_get_pubkey(server_cert)) == NULL)
    BIO_printf(outbio, "Error getting public key from server certificate");

  //verify server
  r2 = X509_verify(server_cert, ca_pkey);
  printf("server signature is %s\n", (r2 == 1) ? "good" : "bad");

  EVP_PKEY_free(ca_pkey);
  X509_free(ca_cert);
  X509_free(server_cert);
  BIO_free_all(ca_certbio);
  BIO_free_all(outbio);
  BIO_free_all(server_certbio);
  
  return r1+r2;
}

int main(int argc, char **argv) {
  int fd, r;
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
  // TODO: Verify server certificate
  r = verify_cert();
  if (r != 2) printf("Verification of server failed\n.");
  
  api_state_init(&state.api, fd, TLS_client_method());
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

  /* clean up */
  /* TODO any additional client cleanup */
  client_state_free(&state);
  close(fd);

  return 0;
}
