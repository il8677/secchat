#ifndef _WORKER_H_
#define _WORKER_H_

struct api_callbacks;

__attribute__((noreturn))
void worker_start(int connfd, int server_fd, char* sharedmem, int index, struct api_callbacks callbacks);

#endif /* !defined(_WORKER_H_) */
