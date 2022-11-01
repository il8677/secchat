#ifndef _WORKER_H_
#define _WORKER_H_

__attribute__((noreturn))
void worker_start(int connfd, int server_fd);

#endif /* !defined(_WORKER_H_) */
