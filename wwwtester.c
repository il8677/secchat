#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "webinterface/route.h"

www_route* routeHead;

/* Simple SSH server that waits for a single connection and then echos any
 * input back to the client.
 * The private key file, server certificate file, and the port to listen on
 * are specified on the command line.
 *
 * Example to run the server:
 * ./ssl-server server-key.pem server-self-cert.pem 1234
 *
 * Example to connect to it (in a separate terminal):
 * ./ssl-client localhost 1234
 *
 * See Makefile and/or slides for how to generate the keys.
 */

int create_server_socket(unsigned short port) {
  int fd, r;
  struct sockaddr_in addr;

  /* create TCP socket */
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) { /* handle error */ }

  /* bind socket to specified port on all interfaces */
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
  if (r != 0) { /* handle error */ }

  /* start listening for incoming client connections */
  r = listen(fd, 0);
  if (r != 0) { /* handle error */ }

  return fd;
}

void sendHeader(SSL* ssl, int length){
  static const char header[] = "HTTP/1.1 200 OK\nconnection: keep-alive\ncontent-length: %d\n\n";
  char formatted[sizeof(header)+5];

  sprintf(formatted, header, length);

  SSL_write(ssl, formatted, strlen(formatted));
}



static void connection_echo(int fd, const char *pathkey, const char *pathcert, int id) {
  char buf[2048];
  int len;

  /* configure SSL */
  SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
  SSL *ssl = SSL_new(ctx);
  SSL_use_certificate_file(ssl, pathcert, SSL_FILETYPE_PEM);
  SSL_use_PrivateKey_file(ssl, pathkey, SSL_FILETYPE_PEM);

  /* set up SSL connection with client */
  SSL_set_fd(ssl, fd);
  SSL_accept(ssl);

  printf("[%d] Connection accepted\n", id);

  /* echo any incoming data from the client */
  for (;;) {
    len = SSL_read(ssl, buf, sizeof(buf));

    if (len <= 0){
      int res;
    
      printf("[%d] Fatal error %d\n", id, res=SSL_get_error(ssl, len));
      if(res == SSL_ERROR_SSL){
        printf("\t(%s)\n", ERR_error_string(ERR_get_error(), NULL));
      }//else if(res == SSL_ERROR_ZERO_RETURN)


      goto cleanup;
    }
    printf("[%d] %d: %.*s\n", id, len, len, buf);

    char* path = strtok(buf, " ");
    path = strtok(NULL, " ");
    
    const char* toSend = www_route_find(routeHead, path);

    if(toSend == NULL){
        printf("[%d] No route %s\n", id, path);
        
        static const char err404[] = "HTTP/1.1 404 Not Found\nconnection: keep-alive\ncontent-length: 0\n\n"; 

        SSL_write(ssl, err404, strlen(err404));
        continue;
    }

      printf("\n[%d] Sending: %s\n\n", id, toSend);
      sendHeader(ssl, strlen(toSend));
      SSL_write(ssl, toSend, strlen(toSend));

  }

  cleanup:
  printf("Worker leaving\n");
  /* clean up SSL */
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  close(fd);

  exit(0);
}

int main(int argc, char **argv) {
    routeHead = www_route_init("/", "www/index.html");
    www_route_initadd(routeHead, "/test1", "www/test1.html");
    www_route_initadd(routeHead, "/test2", "www/test2.html");

  int connfd, servfd;
  unsigned short port;

  int id = 0;

  /* listen for an incoming connection */
  port = atoi(argv[3]);
  servfd = create_server_socket(port);

  printf("Listening port %s\n", argv[3]);

  while (1){
    connfd = accept(servfd, NULL, NULL);

    printf("Recieved connection\n");
    id++;
    pid_t pid = fork();
    if(pid == 0){
      /* interact with client */
      connection_echo(connfd, argv[1], argv[2], id);
    }

    close(connfd);
  }

  /* clean up */
  close(servfd);

  return 0;
}
