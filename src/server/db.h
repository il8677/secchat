#ifndef DB_H
#define DB_H

// This module should be the only database access, outputs from this should be as abstracted from databases as possible

#include <sqlite3.h>
#include "../common/api.h"

struct worker_state;

struct db_state{
    sqlite3* db;
};


/// @brief Initializes a db_state
/// @param state 
/// @return 0 if OK, -1 if error
int db_state_init(struct db_state* state);

/// @brief Frees a db_state
/// @param state 
void db_state_free(struct db_state* state);

/// @brief Calls a callback for unseen messages given a timestamp
/// @param state db state
/// @param astate api state 
/// @param lastViewed the timestamp the messages were last retrieved
/// @param uid the user id to get messages for
/// @param cb the callback to send api_msgs to, returns 0 for no error
/// @return 0 if OK, error code otherwise
int db_get_messages(struct db_state* state, struct worker_state* astate, int uid, int(*cb) (struct worker_state*, struct api_msg*), timestamp_t* lastviewed);

/// @brief Attatches a privkey to an apimsg
/// @param state db state
/// @param msg apimsg to add to
/// @param username The usernames private key to add
/// @return 0 if OK, error code otherwise
int db_attach_privkey(struct db_state* state, struct api_msg* msg, const char* username);

/// @brief Attatches a cert to an apimsg
/// @param state db state
/// @param msg apimsg to add to
/// @param username The usernames cert to add
/// @return 0 if OK, error code otherwise
int db_attatch_cert(struct db_state* state, struct api_msg* msg, const char* username);

/// @brief Adds a public message to the database
/// @param state db state
/// @param msg The API message to add
/// @param uid The UID of the sender
/// @return 0 if OK, ERRCODE otherwise
int db_add_pub_message(struct db_state* state, const struct api_msg* msg, int uid);

/// @brief Adds a public message to the database
/// @param state db state
/// @param msg The API message to add
/// @param uid The UID of the sender
/// @return 0 if OK, ERRCODE otherwise
int db_add_priv_message(struct db_state* state, const struct api_msg* msg, int uid);


/// @brief Registers a user
/// @param state db state
/// @param msg the api message containing the login information
/// @return <0 if error, otherwise the registered user ID
int db_register(struct db_state* state, const struct api_msg* msg);

/// @brief Registers a user
/// @param state db state
/// @param msg the api message containing the login information
/// @return <0 if error, otherwise the registered user ID
int db_login(struct db_state* state, const struct api_msg* msg);

#endif