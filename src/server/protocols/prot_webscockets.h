

char* protwb_processKey(const char *str);

int protwb_notify(struct worker_state*);
int protwb_send(struct worker_state* state, struct api_msg* msg);
int protwb_recv(struct worker_state* state, struct api_msg* msg);