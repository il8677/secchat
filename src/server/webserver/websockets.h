#ifndef WEBSOCKETS_H
#define WEBSOCKETS_H
#include <stdint.h>

struct api_state;

char* protwb_processKey(const char *str);
int send_header(struct api_state* state, uint64_t length, char opcode);

#endif