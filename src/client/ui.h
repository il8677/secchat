
#ifndef _UI_H_
#define _UI_H_

#include "../common/api.h"
#include "linkedlist.h"

struct ui_state {
    struct node* headkey;
    struct node* headtrans;
};

void ui_state_free(struct ui_state* state);
void ui_state_init(struct ui_state* state);

char* read_input(size_t size);
int message_too_long(char* msg); 

int input_handle_privmsg(struct api_msg* apimsg, char* p);
int input_handle_exit(struct api_msg* apimsg, char* p);
int input_handle_users(struct api_msg* apimsg, char* p);
int input_handle_login(struct api_msg* apimsg, char* p);
int input_handle_register(struct api_msg* apimsg, char* p);
int input_handle_pubmsg(struct api_msg* apimsg, char* p);

#endif /* defined(_UI_H_) */
