#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ui.h"
#include "../util/linkedlist.h"
#include "../common/api.h"
#include "../common/errcodes.h"
#include "../util/crypto.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state* state) {
  assert(state);

}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state* state) {
  assert(state);
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

void handle_privmsg_send(RSA* key, X509* selfcert, X509* other, struct api_msg* msg){
  msg->type = PRIV_MSG;

  // The message is stored in frommsg, sign, encrypt and store. The recipient is already set
  // Note: this is from user input, so priv_msg.from *should* be a safe string. strnlen is used for extra safety
  crypto_RSA_sign(key, msg->priv_msg.frommsg, strnlen(msg->priv_msg.frommsg, MAX_MSG_LEN), (unsigned char*)msg->priv_msg.signature);
  crypto_RSA_pubkey_encrypt(msg->priv_msg.tomsg, other, msg->priv_msg.frommsg, strnlen(msg->priv_msg.frommsg, MAX_MSG_LEN-1)+1);
  crypto_RSA_pubkey_encrypt(msg->priv_msg.frommsg, selfcert, msg->priv_msg.frommsg, strnlen(msg->priv_msg.frommsg, MAX_MSG_LEN-1)+1);
}

int input_handle_privmsg(Node* certList, Node* msgQueue, RSA* key, X509* selfcert, struct api_msg* apimsg, char* p) {
  if(selfcert == NULL) return ERR_NO_USER;
  
  p++;

  if (p[0] == ' ') return ERR_NAME_INVALID;

  char *to = strtok(p, " ");
  char *msg = strtok(NULL, ""); 

  if (msg == NULL) return ERR_MESSAGE_INVALID;
  if (message_too_long(msg) == 1) return ERR_MESSAGE_TOOLONG;
  
  while (msg < msg+strlen(msg) && isspace(*msg)) msg++;

  // Find key of person who we're sending a message to
  Node* cert = list_find(certList, to);

  strncpy(apimsg->key.who, to, MAX_USER_LEN);
  strncpy(apimsg->priv_msg.frommsg, msg, MAX_MSG_LEN) ;
  
  if(cert == NULL){ // No key
    // Create key request
    apimsg->type = KEY;

    // Add message to queue
    list_add(msgQueue, to, apimsg, sizeof(struct api_msg), 0);

    // Wipe msg so it isn't leaked to server
    memset(apimsg->priv_msg.frommsg, 0, MAX_MSG_LEN);
  }else{
    handle_privmsg_send(key, selfcert, *(X509**)cert->contents, apimsg);
  }

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

int input_handle_login(struct api_msg* apimsg, char* p, char** passwordout, char** usernameout) {
  char *username = strtok(NULL, " ");
  if (username == NULL) return ERR_NAME_INVALID;

  char *password = strtok(NULL, " ");
  if (password == NULL) return ERR_PASSWORD_INVALID;

  char* tok = strtok(NULL, " ");
  if (tok != NULL) return ERR_INVALID_NR_ARGS;

  if (strlen(username)+1 > MAX_USER_LEN) return ERR_USERNAME_TOOLONG;

  // Store the password / username
  free(*passwordout);
  *passwordout = strdup(password); 
  free(*usernameout);
  *usernameout = strdup(username);

  apimsg->type = LOGIN;
  strncpy(apimsg->login.username, username, MAX_USER_LEN);
  crypto_hash(password, strlen(password), (unsigned char*)apimsg->login.password);

  return 0;
}

int input_handle_register(struct api_msg* apimsg, char* p, char** passwordout, char** usernameout) {
  char *username = strtok(NULL, " ");
  if (username == NULL) return ERR_NAME_INVALID;
  
  char *password = strtok(NULL, " ");
  if (password == NULL) return ERR_PASSWORD_INVALID;

  if (strlen(username)+1 > MAX_USER_LEN) return ERR_USERNAME_TOOLONG;

  char* tok = strtok(NULL, " ");
  if (tok != NULL) return ERR_INVALID_NR_ARGS;
  
  // Store the password / username
  free(*passwordout);
  *passwordout = strdup(password);
  free(*usernameout);
  *usernameout = strdup(username);

  apimsg->type = REG;
  strncpy(apimsg->reg.username, username, MAX_USER_LEN);
  crypto_hash(password, strlen(password), (unsigned char*)apimsg->login.password);

  crypto_get_user_auth(username, &apimsg->encPrivKey, &apimsg->cert);
  char* enc = crypto_aes_encrypt(apimsg->encPrivKey, strlen(apimsg->encPrivKey)+1, password, username, 1, &apimsg->encPrivKeyLen);
  free(apimsg->encPrivKey);
  apimsg->encPrivKey= enc;

  apimsg->certLen = strlen(apimsg->cert) + 1;

  return 0;
}

int input_handle_pubmsg(RSA* key, struct api_msg* apimsg, char* p) {
  if(key == NULL) return ERR_NO_USER;


  char *p_start = p;
  char *p_last = p + strlen(p) -1;

  while (p_last > p_start && isspace(*p_last)) p_last--;

  p_last[1] = '\0';
    
  if (message_too_long(p_start)) return ERR_MESSAGE_TOOLONG;
  
  apimsg->type = PUB_MSG;
  strncpy(apimsg->pub_msg.msg, p_start, MAX_MSG_LEN);

  crypto_RSA_sign(key, p_start, strlen(p_start), (unsigned char*)apimsg->pub_msg.signature); 

  return 0;
}
