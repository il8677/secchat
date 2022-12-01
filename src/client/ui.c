#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ui.h"
#include "../common/api.h"
#include "../common/errcodes.h"
#include "../util/crypto.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state* state) {
  assert(state);

    // Clean up linked lists
  list_free(state->headkey); // TODO: need &? :)
  list_free(state->headtrans);
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state* state) {
  assert(state);

    //initialize linked lists
  state->headkey = list_init();
  state->headtrans = list_init();
}

/**
 * @brief         Reads inputs from user
 * @param size    Initial size of the buffer       
*/
char *read_input(size_t size) {
  char *input = malloc(size);
  int c;
  size_t len = 0;

  while ('\n' != (c = fgetc(stdin))) {
    if (c == EOF) {
      free(input); 
      return NULL;
    }
    input[len++] = c;
    if (len == size) {
      input = realloc(input, sizeof(*input)*(size+=16));
    }
  }

  input[len++] = '\0';
  input = realloc(input, sizeof(*input)*size);

  return input;
}

/**
 * @brief         Checks if user message is too long
 * @param msg     Msg of user to check
*/
int message_too_long(char* msg) {
  return strlen(msg)+1 > MAX_MSG_LEN;  
}

int privmsg_encrypt(struct client_state* state, struct api_msg* msg){
    if(msg->type == PRIV_MSG){
    struct api_msg* encrypted_msg_rec = (api_msg*)malloc sizeof(struct api_msg);
    struct api_msg* encrypted_msg_sender = (api_msg*)malloc sizeof(struct api_msg);
    int len = strlen(msg->priv_msg.msg);
  	struct node* keynode = list_exist(state->headkey, msg->priv_msg.to);
    if ( keynode == NULL) {
      list_add(state->headtrans, msg->priv_msg.to, msg ,len); //prob doesnt work but the data should be the msg no?
      return;
    }
    
    // TODO:: stop with trolling
    encrypted_msg_rec->priv_msg.to = msg->priv_msg.to;
    encrypted_msg_rec->priv_msg.from = msg->priv_msg.from;
    encrypted_msg_rec->priv_msg.timestamp = msg->priv_msg.timestamp;

    encrypted_msg_sender->priv_msg.to = msg->priv_msg.to;
    encrypted_msg_sender->priv_msg.from = msg->priv_msg.from;
    encrypted_msg_sender->priv_msg.timestamp = msg->priv_msg.timestamp;


    //if not in keylist add request to list return
    // if(len > MAX_MSG_LEN){
    //   return -1;
    // }
    
    RSA_public_encrypt(len,msg->priv_msg.msg, encrypted_msg_rec.priv_msg.msg, keynode->contents , RSA_PKCS1_OAEP_PADDING);
    RSA_public_encrypt(len,msg->priv_msg.msg, encrypted_msg_sender.priv_msg.msg, keynode->contents, RSA_PKCS1_OAEP_PADDING);
  }
}

int input_handle_privmsg(struct client_state* state, struct api_msg* apimsg, char* p) {
  p++;

  if (p[0] == ' ') return ERR_NAME_INVALID;

  char *to = strtok(p, " ");
  char *msg = strtok(NULL, ""); 

  if (msg == NULL) return ERR_MESSAGE_INVALID;
  if (message_too_long(msg) == 1) return ERR_MESSAGE_TOOLONG;
  
  while (msg < msg+strlen(msg) && isspace(*msg)) msg++;

  apimsg->type = PRIV_MSG;
  strncpy(apimsg->priv_msg.to, to, MAX_USER_LEN);
  strncpy(apimsg->priv_msg.msg, msg, MAX_MSG_LEN); 

  privmsg_encrypt(state, apimsg);
  return 0;
}


int input_handle_exit(struct api_msg* apimsg, char* p) {
  char* tok = strtok(NULL, " ");

  if (tok != NULL) return ERR_INVALID_NR_ARGS;

  apimsg->type = EXIT;
  return 0;
}

int input_handle_users(struct api_msg* apimsg, char* p) {
  char* tok = strtok(NULL, " ");

  if (tok != NULL) return ERR_INVALID_NR_ARGS;

  apimsg->type = WHO;
  return 0;
}

int input_handle_login(struct api_msg* apimsg, char* p) {
  char *username = strtok(NULL, " ");
  if (username == NULL) return ERR_NAME_INVALID;

  char *password = strtok(NULL, " ");
  if (password == NULL) return ERR_PASSWORD_INVALID;

  char* tok = strtok(NULL, " ");
  if (tok != NULL) return ERR_INVALID_NR_ARGS;

  if (strlen(username)+1 > MAX_USER_LEN) return ERR_USERNAME_TOOLONG;

  apimsg->type = LOGIN;
  strncpy(apimsg->login.username, username, MAX_USER_LEN);
  hash(password, strlen(password), (unsigned char*)apimsg->login.password);

  return 0;
}
int input_handle_register(struct api_msg* apimsg, char* p) {
  char *username = strtok(NULL, " ");
  if (username == NULL) return ERR_NAME_INVALID;
  
  char *password = strtok(NULL, " ");
  if (password == NULL) return ERR_PASSWORD_INVALID;

  if (strlen(username)+1 > MAX_USER_LEN) return ERR_USERNAME_TOOLONG;

  char* tok = strtok(NULL, " ");
  if (tok != NULL) return ERR_INVALID_NR_ARGS;
  
  apimsg->type = REG;
  strncpy(apimsg->reg.username, username, MAX_USER_LEN);
  hash(password, strlen(password), (unsigned char*)apimsg->login.password);
  
  return 0;
}
int input_handle_pubmsg(struct api_msg* apimsg, char* p) {
  char *p_start = p;
  char *p_last = p + strlen(p) -1;

  while (p_last > p_start && isspace(*p_last)) p_last--;

  p_last[1] = '\0';
    
  if (message_too_long(p_start)) return ERR_MESSAGE_TOOLONG;
  
  apimsg->type = PUB_MSG;
  strncpy(apimsg->pub_msg.msg, p_start, MAX_MSG_LEN);
  
  return 0;
}
