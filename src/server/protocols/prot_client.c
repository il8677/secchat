#include "../worker/workerapi.h"
#include "../db.h"

#include "../../common/api.h"

int protc_send(struct worker_state* state, struct api_msg* msg){
    return api_send(&state->api, msg);
}

int protc_recv(struct worker_state* state, struct api_msg* msg){
    return api_recv(&state->api, msg);
}