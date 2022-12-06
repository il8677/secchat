// Taken from examples
#ifndef __SSL_NONBLOCK_H__
#define __SSL_NONBLOCK_H__

#include <openssl/ssl.h>

/* These functions allow SSL to be combined with select:
 * - Set the file descriptor of the socket to non-blocking mode using
 *   set_nonblock() before passing it to OpenSSL
 * - If select() claims there is data available, use ssl_has_data() to check
 *   whether it is indeed user data (rather than just SSL protocol overhead).
 * - The other functions allow the regular SSL operations to be done in a
 *   blocking way on a non-blocking SSL object, to require minimal code changes.
 */

int ssl_block_accept(SSL *ssl, int fd);
int ssl_block_connect(SSL *ssl, int fd);
int ssl_block_read(SSL *ssl, int fd, void *buf, int len);
int ssl_block_write(SSL *ssl, int fd, const void *buf, int len);
int ssl_has_data(SSL *ssl);
int set_nonblock(int fd);

#endif