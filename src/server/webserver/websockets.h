#ifndef WEBSOCKETS_H
#define WEBSOCKETS_H
#include <stdint.h>

struct api_state;

/// @brief Calclates the return key for websockets (required by protocol)
/// @param str The given key
/// @return The return key
char* protwb_processKey(const char *key);

/// @brief Send a websocket frame header
/// @param state The api_state to send to
/// @param length The length of the payload
/// @param opcode The opcode
/// @return Amounts of bytes written, or -1 if failure
int send_header(struct api_state* state, uint64_t length, char opcode);

#endif