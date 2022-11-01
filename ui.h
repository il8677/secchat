#ifndef _UI_H_
#define _UI_H_

struct ui_state {
  /* TODO add fields to store the command arguments */
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);

/* TODO add UI calls interact with user on stdin/stdout */

#endif /* defined(_UI_H_) */
