#include <string.h>
#include <stdio.h>
#include <time.h>

#include "db.h"
#include "errcodes.h"

// Macros to stringify other macros
// STR2 stringifies input, STR expands to STR2(x), so x will be expanded and stringified. C is such a quaint language.
#define STR2(x) #x
#define STR(x) STR2(x)

/// @brief Executes a sqlite3 call, checking for a returned error message and printing it if theres an error
/// @param x The statement to execute
/// @param db The database to get the error message from
/// @param ret The error return value
#define SQL_CALL(x, db, ret) if(SQLITE_OK != (x)) { fprintf(stderr, "Line %d: Error running " STR2(x) "\n\t%s\n", __LINE__, sqlite3_errmsg(db)); return ret;}

/// @brief Executes a sql statement
/// @param db the database
/// @param x the sql statement
/// @param callback the callback function
/// @param userdata userdata for the callback function
/// @return 0 if ok, a SQL error code otherwise
int sql_exec(sqlite3* db, const char* x, int (*callback)(void*,int,char**,char**), void* userdata) {
    char* errmsg = NULL;
    int res = sqlite3_exec(db, x, callback, userdata, &errmsg);

    if(res != SQLITE_OK){
        fprintf(stderr, "Error running %s\n\t%s\n", x, errmsg);
        sqlite3_free(errmsg);
    }

    return res;
}

/// @brief Creates a database and tables
/// @param state db state
void db_create(struct db_state* state){
    // NOTE: 1 must be subtracted from char lengths because of the null byte
    sqlite3_extended_result_codes(state->db, 1);

    sql_exec(state->db, "PRAGMA foreign_keys = ON;", NULL, NULL);

    // Create user DB
    sql_exec(state->db, 
    "CREATE TABLE IF NOT EXISTS users ( \
        id INTEGER PRIMARY KEY AUTOINCREMENT, \
        username VARCHAR(" STR(MAX_USER_LEN_M1) ") NOT NULL UNIQUE, \
        password VARCHAR(" STR(MAX_USER_LEN_M1) ") NOT NULL, \
        lastviewed INTEGER DEFAULT 0 NOT NULL);", 
    NULL, NULL);

    // Create message db
    sql_exec(state->db, 
    "CREATE TABLE IF NOT EXISTS messages ( \
        id INTEGER PRIMARY KEY AUTOINCREMENT, \
        sender INTEGER NOT NULL, \
        recipient INTEGER DEFAULT NULL, \
        msg VARCHAR(" STR(MAX_MSG_LEN_M1) ") NOT NULL, \
        timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')), \
        FOREIGN KEY(sender) REFERENCES users(id),\
        FOREIGN KEY(recipient) REFERENCES users(id));", 
    NULL, NULL);
}

int db_get_messages(struct db_state* state, struct api_state* astate, timestamp_t lastViewed, int uid, int(*cb) (struct api_state*, struct api_msg*)){
    char* query = sqlite3_mprintf("SELECT su.username, ru.username, msg, timestamp \
                            FROM messages INNER JOIN users AS su ON su.id == sender \
                            LEFT JOIN users AS ru ON ru.id == recipient \
                            WHERE timestamp > %d AND (recipient IS NULL OR recipient == %d)", lastViewed, uid);


    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, -1);

    int res = sqlite3_step(statement);;

    while(res == SQLITE_ROW){
        // Create api_msg to represent the row
        struct api_msg row;

        // These do NOT have to be freed (they are freed by finalize)
        const char* sender = (const char*)sqlite3_column_text(statement, 0);
        const char* recipient = (const char*)sqlite3_column_text(statement, 1);

        const char* msg = (const char*)sqlite3_column_text(statement, 2);
        timestamp_t timestamp = sqlite3_column_int64(statement, 3);

        // The offsets should be the same so priv_msg and pub_msg should be equivalent
        row.priv_msg.timestamp = timestamp;

        // string should be of correct length, but just to be safe
        strncpy(row.priv_msg.msg, msg, MAX_MSG_LEN);
        row.priv_msg.msg[MAX_MSG_LEN-1] = '\0';
        
        
        strncpy(row.priv_msg.from, sender, MAX_USER_LEN);
        row.priv_msg.msg[MAX_USER_LEN-1] = '\0';

        row.type = PUB_MSG;

        if(recipient != NULL){
            strncpy(row.priv_msg.to, recipient, MAX_USER_LEN);
            row.priv_msg.msg[MAX_USER_LEN-1] = '\0';

            row.type=PRIV_MSG;
        }

        // We can reuse res since it will be ovewritten
        if((res = cb(astate, &row))) return res;

        res = sqlite3_step(statement);
    }

    sqlite3_finalize(statement);
    sqlite3_free(query);

    return 0;
}

/// @brief Returns an ID for name
/// @param state db state
/// @param name the name to search for
/// @return the ID of the name, or ERR_NAME_INVALID if it doesn't exist
int nametoid(struct db_state* state, const char* name){
    int retvalue = ERR_NAME_INVALID;
    char* query = sqlite3_mprintf("SELECT id FROM users WHERE username=\"%s\";", name);
    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, -1);

    // If there was a result, the name was found
    if(sqlite3_step(statement) == SQLITE_ROW)
        retvalue = sqlite3_column_int(statement, 0);
    

    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;
}

/// @brief Verifies a username / password pair is correct
/// @param state db state
/// @return Userid if correct, ERR_INCORECT_LOGIN if not

int verify_login(struct db_state* state, const char* username, const char* password){
    int retvalue = ERR_INCORRECT_LOGIN;

    char* query = sqlite3_mprintf("SELECT id FROM users WHERE username=\"%s\" AND password=\"%s\";", username, password);
    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, -1);

    // If there was a result, user / password is correct
    if(sqlite3_step(statement) == SQLITE_ROW)
        retvalue = sqlite3_column_int(statement, 0);
    

    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;

}

int db_add_message(struct db_state* state, struct api_msg* msg, int uid){
    char* query = NULL;

    if(msg->type == PRIV_MSG){
        int id = nametoid(state, msg->priv_msg.to);

        // If error
        if(id < 0) return id;

        query = sqlite3_mprintf("INSERT INTO messages (sender, recipient, msg) VALUES (%i, %i, \"%s\");", uid, id, msg->priv_msg.msg);

    }else if(msg->type == PUB_MSG){
        query = sqlite3_mprintf("INSERT INTO messages (sender, msg) VALUES (%i, \"%s\");", uid, msg->pub_msg.msg);
    }else{
        return ERR_INVALID_API_MSG;
    }

    int res = sql_exec(state->db, query, NULL, NULL);

        sqlite3_free(query);
    if(res != SQLITE_OK)
        return ERR_SQL;
    
    return 0;
}

int db_state_init(struct db_state* state){
    int res = sqlite3_open("chat.db", &(state->db));

    if(res){
        fprintf(stderr, "Can't open database %s\n", sqlite3_errmsg(state->db));
        sqlite3_close(state->db);

        return -1;
    }

    db_create(state);

    return 0;
}

int db_register(struct db_state* state, struct api_msg* msg){
    if(msg->type != REG) return ERR_INVALID_API_MSG;

    char* query = sqlite3_mprintf("INSERT INTO users (username, password) VALUES(\"%s\", \"%s\");", msg->reg.username, msg->reg.password);

    int res = sql_exec(state->db, query, NULL, NULL);

    if(res == SQLITE_CONSTRAINT_UNIQUE) return ERR_USERNAME_EXISTS;
    else if(res != SQLITE_OK) return ERR_SQL;

    sqlite3_free(query);

    return nametoid(state, msg->reg.username);
}

int db_login(struct db_state* state, struct api_msg* msg){
    if(msg->type != LOGIN) return ERR_INVALID_API_MSG;

    return verify_login(state, msg->login.username, msg->login.password);
}

void db_state_free(struct db_state* state){
    sqlite3_close(state->db);
}

