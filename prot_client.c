#include "workerapi.h"
#include "db.h"

#include "api.h"

static int msg_query_cb(struct api_state* state, struct api_msg* msg){
  return api_send(state, msg) == 1 ? 0 : -1;
}

int protc_handle_s2w(struct worker_state* state) {
  db_get_messages(&state->dbConn, &state->api, state->uid, msg_query_cb, &state->lastviewed);

  return 0;
};
