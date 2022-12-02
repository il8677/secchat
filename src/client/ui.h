
#ifndef _UI_H_
#define _UI_H_

#include "../common/api.h"
#include "linkedlist.h"
#include <openssl/ssl.h>

RSA* d_privkey;

struct ui_state {
    
};

void ui_state_free(struct ui_state* state);
void ui_state_init(struct ui_state* state);

char* read_input(size_t size);
int message_too_long(char* msg); 

int input_handle_privmsg(Node* certList, Node* msgQueue, X509* selfcert, struct api_msg* apimsg, char* p);
int input_handle_exit(struct api_msg* apimsg, char* p);
int input_handle_users(struct api_msg* apimsg, char* p);
int input_handle_login(struct api_msg* apimsg, char* p, char** passwordout);
int input_handle_register(struct api_msg* apimsg, char* p, char** passwordout);
int input_handle_pubmsg(struct api_msg* apimsg, char* p);

/// @brief Formats message as a privkey
/// @param selfcert 
/// @param other 
/// @param msg 
void handle_privmsg_send(X509* selfcert, X509* other, struct api_msg* msg);

#endif /* defined(_UI_H_) */
