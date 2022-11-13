#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "ui.h"
#include "api.h"
#include "errcodes.h"

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
    if (c == EOF) return NULL;
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
  return strlen(msg) > MAX_MSG_LEN;  
}

int input_handle_privmsg(struct api_msg* apimsg, char* p) {
  p++;

  if (p[0] == ' ') return ERR_NAME_INVALID;

  char *to = strtok(p, " ");
  char *msg = strtok(NULL, ""); 

  if (msg == NULL) return ERR_MESSAGE_INVALID;
  if (message_too_long(msg) == 1) return ERR_MESSAGE_TOOLONG;

  apimsg->type = PRIV_MSG;
  strcpy(apimsg->priv_msg.to, to);
  strcpy(apimsg->priv_msg.msg, msg); 

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

  if (strlen(username) > MAX_USER_LEN) return ERR_USERNAME_TOOLONG;
  if (strlen(password) > MAX_USER_LEN) return ERR_PASSWORD_TOOLONG;

  apimsg->type = LOGIN;
  strcpy(apimsg->login.username, username);
  strcpy(apimsg->login.password, password);

  return 0;
}
int input_handle_register(struct api_msg* apimsg, char* p) {
  char *username = strtok(NULL, " ");
  if (username == NULL) return ERR_NAME_INVALID;
  
  char *password = strtok(NULL, " ");
  if (password == NULL) return ERR_PASSWORD_INVALID;

  if (strlen(username) > MAX_USER_LEN) return ERR_USERNAME_TOOLONG;
  if (strlen(password) > MAX_USER_LEN) return ERR_PASSWORD_TOOLONG;

  char* tok = strtok(NULL, " ");
  if (tok != NULL) return ERR_INVALID_NR_ARGS;
  
  apimsg->type = REG;
  strcpy(apimsg->reg.username, username);
  strcpy(apimsg->reg.password, password);
  
  return 0;
}
int input_handle_pubmsg(struct api_msg* apimsg, char* p) {
  char *p_start = p;
  char *p_last = p + strlen(p) -1;

  while (p_last > p_start && isspace(*p_last)) p_last--;

  p_last[1] = '\0';
    
  if (message_too_long(p_start)) return ERR_MESSAGE_TOOLONG;
  
  apimsg->type = PUB_MSG;
  strcpy(apimsg->pub_msg.msg, p_start);
  
  return 0;
}
