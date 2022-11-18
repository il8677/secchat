// Taken from examples

#include <fcntl.h>
#include <openssl/err.h>

#include "ssl-nonblock.h"

/* see header file for explanation */

static int ssl_block_if_needed(SSL *ssl, int fd, int r) {
  int err, want_read;
  fd_set readfds, writefds;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *    1: more data available
   */

  /* do we need more input/output? */
  err = SSL_get_error(ssl, r);
  switch (err) {
  case SSL_ERROR_ZERO_RETURN: return 0;
  case SSL_ERROR_WANT_READ:   want_read = 1; break;
  case SSL_ERROR_WANT_WRITE:  want_read = 0; break;
  default:
    if (err == SSL_ERROR_SYSCALL && !ERR_peek_error()) return 0;

    fprintf(stderr, "SSL call failed, err=%d\n", err);
    ERR_print_errors_fp(stderr);
    return -1;
  }

  /* wait for more input/output */
  FD_ZERO(&readfds);
  FD_ZERO(&writefds);
  FD_SET(fd, want_read ? &readfds : &writefds);
  r = select(fd+1, &readfds, &writefds, NULL, NULL);
  if (r != 1) return -1;

  return 1;
}

int ssl_block_accept(SSL *ssl, int fd) {
  int r;

  /* return value:
   *   -1: error
   *    1: success
   */

  /* block until the call succeeds */
  for (;;) {
    r = SSL_accept(ssl);
    if (r == 1) return 1;
    r = ssl_block_if_needed(ssl, fd, r);
    if (r != 1) return -1;
  }
}

int ssl_block_connect(SSL *ssl, int fd) {
  int r;

  /* return value:
   *   -1: error
   *    1: success
   */

  /* block until the call succeeds */
  for (;;) {
    r = SSL_connect(ssl);
    if (r == 1) return 1;
    r = ssl_block_if_needed(ssl, fd, r);
    if (r != 1) return -1;
  }
}

int ssl_block_read(SSL *ssl, int fd, void *buf, int len) {
  char *p = buf, *pend = p + len;
  int r;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *   >0: number of bytes read
   */

  /* we may need to do multiple reads in case one returns prematurely */
  while (p < pend) {
    /* attempt to read */
    r = SSL_read(ssl, p, pend - p);
    if (r > 0) {
      p += r;
      break;
    }

    /* do we need to block? */
    r = ssl_block_if_needed(ssl, fd, r);
    if (r < 0) return -1;
    if (r == 0) break;
  }

  return p - (char *) buf;
}

int ssl_block_write(SSL *ssl, int fd, const void *buf, int len) {
  const char *p = buf, *pend = p + len;
  int r;

  /* return value:
   *   -1: error
   *    0: end-of-file
   *   >0: number of bytes written
   */

  /* we may need to do multiple writes in case one returns prematurely */
  while (p < pend) {
    /* attempt to write */
    r = SSL_write(ssl, p, pend - p);
    if (r > 0) {
      p += r;
      break;
    }
    
    /* do we need to block? */
    r = ssl_block_if_needed(ssl, fd, r);
    if (r < 0) return -1;
    if (r == 0) break;
  }

  return p - (char *) buf;
}

int ssl_has_data(SSL *ssl) {
  char byte;
  int r;

  /* return value:
   *   0: nothing available
   *   1: data, end-of-file, or error available
   */

  /* verify that at least one byte of user data is available */
  r = SSL_peek(ssl, &byte, sizeof(byte));
  return r > 0 || SSL_get_error(ssl, r) != SSL_ERROR_WANT_READ;
}

int set_nonblock(int fd) {
  int flags, r;

  /* return value:
   *   -1: error
   *    0: success
   */

  /* set O_NONBLOCK flag on given file descriptor */
  flags = fcntl(fd, F_GETFL);
  if (flags == -1) return -1;
  r = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (r == -1) return -1;
  return 0;
}