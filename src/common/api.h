#ifndef _API_H_
#define _API_H_

#include <stdint.h>
#include <openssl/ssl.h>

#define MAX_USER_LEN 10
#define MAX_MSG_LEN 160

// Because preprocessors cannot do athrithmetic 
#define MAX_USER_LEN_M1 9
#define MAX_MSG_LEN_M1 159

#define MAX_CONNECTIONS 16

#define API_DEBUG
#ifdef API_DEBUG
  #define API_PRINT_MSG(dmsg, apimsg) switch(apimsg.type){\
    case NONE: printf("["dmsg"] None\n"); break;\
    case ERR: printf("["dmsg"] ERR %d\n", apimsg.errcode); break;\
    case STATUS: printf("["dmsg"] STATUS %.*s\n", MAX_MSG_LEN, apimsg.status.statusmsg); break;\
    case PRIV_MSG: printf("["dmsg"] MSG %.*s -> %.*s: %.*s\n", MAX_USER_LEN, apimsg.priv_msg.from, MAX_USER_LEN, apimsg.priv_msg.to, MAX_MSG_LEN, apimsg.priv_msg.msg); break;\
    case PUB_MSG: printf("["dmsg"] MSG %.*s: %.*s\n", MAX_USER_LEN, apimsg.pub_msg.from, MAX_MSG_LEN, apimsg.pub_msg.msg); break;\
    case WHO: printf("["dmsg"] WHO\n"); break;\
    case REG: case LOGIN: printf("["dmsg"] LOGIN/REG %.*s %.*s\n", MAX_USER_LEN, apimsg.reg.username, MAX_USER_LEN, apimsg.reg.password); break;\
    case EXIT: printf("["dmsg"] EXIT\n"); break;\
    default: printf("["dmsg"] UNRECONGIZED\n"); break;\
  }
#else
  #define API_PRINT_MSG(msg, apimsg)
#endif

enum msg_type_t {NONE, ERR, STATUS, PRIV_MSG, PUB_MSG, WHO, LOGIN, REG, EXIT, KEY };

typedef signed long timestamp_t;

/// @brief The struct of data to be sent over the wire
struct api_msg {
  // TODO: Auth info

  enum msg_type_t type;

  char errcode;

  union {
    struct {
      char statusmsg[MAX_MSG_LEN];
    } status;

    struct {
      timestamp_t timestamp;

      char msg[MAX_MSG_LEN];

      char from[MAX_USER_LEN];
      char to[MAX_USER_LEN];
    } priv_msg;

    struct {
      timestamp_t timestamp;

      char msg[MAX_MSG_LEN];

      char from[MAX_USER_LEN];
    } pub_msg;

    struct {
      char users[MAX_MSG_LEN];
    } who;

    struct {
      //TODO: the actual type of a key
      char *key;
      char *owner;
    } key;

    struct {
      char username[MAX_USER_LEN];
      char password[SHA_DIGEST_LENGTH];
    } login;

    struct {
      char username[MAX_USER_LEN];
      char password[SHA_DIGEST_LENGTH];  
    } reg;

    struct {
    } exit;
  };
};

struct api_state {
  int fd;

  SSL_CTX* ctx;
  SSL* ssl;
};

int api_recv(struct api_state* state, struct api_msg* msg);
void api_recv_free(struct api_msg* msg);
int api_send(struct api_state* state, struct api_msg* msg);

void api_state_free(struct api_state* state);
void api_state_init(struct api_state* state, int fd, const SSL_METHOD* method);

#endif /* defined(_API_H_) */
