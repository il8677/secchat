#include <string.h>
#include <stdio.h>
#include <time.h>

#include "db.h"
#include "../common/errcodes.h"

#include <openssl/sha.h>

// Macros to stringify other macros
// STR2 stringifies input, STR expands to STR2(x), so x will be expanded and stringified. C is such a quaint language.
#define STR2(x) #x
#define STR(x) STR2(x)

/// @brief Executes a sqlite3 call, checking for a returned error message and printing it if theres an error
/// @param x The statement to execute
/// @param db The database to get the error message from
/// @param ret The error return value
/// @param retvar Where to put the return
#define SQL_CALL(x, db, ret, retvar) if(SQLITE_OK != (x)) { fprintf(stderr, "Line %d: Error running " STR2(x) "\n\t%s\n", __LINE__, sqlite3_errmsg(db)); retvar = ret; goto cleanup; }

/// @brief Executes a sql statement
/// @param db the database
/// @param x the sql statement
/// @param callback the callback function
/// @param userdata userdata for the callback function
/// @return 0 if ok, a SQL error code otherwise
int sql_exec(sqlite3* db, const char* x, int (*callback)(void*,int,char**,char**), void* userdata) {
    char* errmsg = NULL;
    int res = SQLITE_BUSY;

    while(res == SQLITE_BUSY) res = sqlite3_exec(db, x, callback, userdata, &errmsg);

    if(res != SQLITE_OK){
        fprintf(stdout, "Error running %s\n\t%s\n", x, errmsg);
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
    sql_exec(state->db, "PRAGMA journal_mode = WAL;", NULL, NULL);

    // Create user DB
    // Private key is aes encrypted so it's a blob (it might contain null bytes)
    // The cert is just a plaintext so we can deal with it as a string
    sql_exec(state->db, 
    "CREATE TABLE IF NOT EXISTS users ( \
        id INTEGER PRIMARY KEY AUTOINCREMENT, \
        username VARCHAR(" STR(MAX_USER_LEN_M1) ") NOT NULL UNIQUE, \
        password BLOB(" STR(SHA256_DIGEST_LENGTH) ") NOT NULL,\
        privkey BLOB("STR(MAX_PRIVKEY)") NOT NULL, \
        cert VARCHAR("STR(MAX_CERT)") NOT NULL);", 
    NULL, NULL);

    // Create message DB
    sql_exec(state->db, 
    "CREATE TABLE IF NOT EXISTS messages ( \
        id INTEGER PRIMARY KEY AUTOINCREMENT, \
        timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')), \
        sender INTEGER NOT NULL, \
        signature BLOB("STR(MAX_ENCRYPT_LEN)") NOT NULL, \
        FOREIGN KEY(sender) REFERENCES users(id))",
    NULL, NULL);

    // Create public message db
    sql_exec(state->db, 
    "CREATE TABLE IF NOT EXISTS pub_messages ( \
        id INTEGER PRIMARY KEY, \
        msg VARCHAR(" STR(MAX_MSG_LEN_M1) ") NOT NULL, \
        FOREIGN KEY(id) REFERENCES messages(id))", 
    NULL, NULL);

    // Create DM db
    sql_exec(state->db,
    "CREATE TABLE IF NOT EXISTS priv_messages( \
        id INTEGER PRIMARY KEY, \
        recipient INTEGER NOT NULL, \
        sendermsg BLOB("STR(MAX_ENCRYPT_LEN)") NOT NULL, \
        recipientmsg BLOB("STR(MAX_ENCRYPT_LEN)") NOT NULL, \
        FOREIGN KEY(recipient) REFERENCES users(id), \
        FOREIGN KEY(id) REFERENCES messages(id))", NULL, NULL);
}

int db_get_messages(struct db_state* state, struct worker_state* astate, int uid, int(*cb) (struct worker_state*, struct api_msg*), timestamp_t* lastviewed){

    // Big statement, creates a union between the public messages, private messages where the user is the sender, and private messages where the user is the recipient,
    // selecting for the appropriate encrypted msg out of the pair.
    char* query = sqlite3_mprintf("SELECT q1.id, q1.signature, q1.timestamp, su.username, ru.username, q1.msg FROM \
        (SELECT messages.id, messages.signature, timestamp, sender, NULL AS recipient, msg FROM pub_messages LEFT JOIN messages ON messages.id == pub_messages.id \
        UNION ALL \
        SELECT messages.id, messages.signature, timestamp, sender, recipient, sendermsg FROM priv_messages LEFT JOIN messages ON messages.id == priv_messages.id WHERE sender == %d \
        UNION ALL \
        SELECT messages.id, messages.signature, timestamp, sender, recipient, recipientmsg FROM priv_messages LEFT JOIN messages ON messages.id == priv_messages.id WHERE recipient == %d) AS q1 \
        LEFT JOIN users AS su ON su.id == q1.sender \
        LEFT JOIN users AS ru ON ru.id == q1.recipient \
        WHERE q1.id > %i ORDER BY q1.id ASC;", 
        uid, uid, *lastviewed);

    sqlite3_stmt* statement;

    int retvalue = 0;
    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, ERR_SQL, retvalue);

    int res = sqlite3_step(statement);
    
    while(res == SQLITE_ROW){
        // Create api_msg to represent the row
        struct api_msg row;
        api_msg_init(&row);

        *lastviewed = sqlite3_column_int64(statement, 0);
        
        // These do NOT have to be freed (they are freed by finalize)
        const char* signature = sqlite3_column_blob(statement, 1);
        timestamp_t timestamp = sqlite3_column_int64(statement, 2);
        const char* sender = (const char*)sqlite3_column_text(statement, 3);
        const char* recipient = (const char*)sqlite3_column_text(statement, 4);

        const unsigned char* msg;
        if(recipient == NULL){
            msg = sqlite3_column_text(statement, 5);
            // string should be of correct length, but just to be safe
            strncpy(row.pub_msg.msg, (const char*)msg, MAX_MSG_LEN);
            row.pub_msg.msg[MAX_MSG_LEN-1] = '\0';
            
            row.type = PUB_MSG;
        }else{
            msg = sqlite3_column_blob(statement, 5);
            memcpy(row.priv_msg.frommsg, msg, MAX_ENCRYPT_LEN);
            strncpy(row.priv_msg.to, recipient, MAX_USER_LEN);
            row.priv_msg.to[MAX_USER_LEN-1] = '\0';

            row.type=PRIV_MSG;
        }

        // The offsets should be the same so priv_msg and pub_msg should be equivalent
        row.priv_msg.timestamp = timestamp;

        strncpy(row.priv_msg.from, sender, MAX_USER_LEN);
        row.priv_msg.from[MAX_USER_LEN-1] = '\0';

        memcpy(row.pub_msg.signature, signature, MAX_ENCRYPT_LEN);

        if((retvalue = cb(astate, &row))) goto cleanup;

        api_msg_free(&row);
        res = sqlite3_step(statement);
    }

    cleanup:
    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;
    return 0;
}

/// @brief Returns an ID for name
/// @param state db state
/// @param name the name to search for
/// @return the ID of the name, or ERR_NAME_INVALID if it doesn't exist
int nametoid(struct db_state* state, const char* name){
    int retvalue = ERR_NO_USER; // User id invalid by default
    char* query = sqlite3_mprintf("SELECT id FROM users WHERE username=%Q;", name);
    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, ERR_SQL, retvalue);

    // If there was a result, the name was found
    if(sqlite3_step(statement) == SQLITE_ROW)
        retvalue = sqlite3_column_int(statement, 0);
    

    cleanup:
    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;
}

/// @brief Verifies a username / password pair is correct
/// @param state db state
/// @return Userid if correct, ERR_INCORECT_LOGIN if not
int verify_login(struct db_state* state, const char* username, const char* password){
    int retvalue = ERR_INCORRECT_LOGIN;

    char* query = sqlite3_mprintf("SELECT id FROM users WHERE username=%Q AND password=%Q;", username, password);
    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, ERR_SQL, retvalue);

    // If there was a result, user / password is correct
    if(sqlite3_step(statement) == SQLITE_ROW)
        retvalue = sqlite3_column_int(statement, 0);
    
    cleanup:
    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;

}

int db_add_privkey(struct db_state* state, struct api_msg* msg, const char* username){
    int id = nametoid(state, username);
    int retvalue = 0;
    if(id < 0) return id;

    char* query = sqlite3_mprintf("SELECT privkey, LENGTH(privkey) FROM users WHERE id=%d;", id);
    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, ERR_SQL, retvalue);

    if(sqlite3_step(statement) == SQLITE_ROW){
        msg->encPrivKeyLen = sqlite3_column_int(statement, 1);
        msg->encPrivKey = malloc(msg->encPrivKeyLen);
        memcpy(msg->encPrivKey, sqlite3_column_blob(statement, 0), msg->encPrivKeyLen);
    }
    
    cleanup:
    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;
}


int db_add_cert(struct db_state* state, struct api_msg* msg, const char* username){
    int id = nametoid(state, username);
    int retvalue = 0;
    if(id < 0) return id;

    char* query = sqlite3_mprintf("SELECT cert FROM users WHERE id=%d;", id);
    sqlite3_stmt* statement;

    SQL_CALL(sqlite3_prepare(state->db, query, -1, &statement, 0), state->db, ERR_SQL, retvalue);

    if(sqlite3_step(statement) == SQLITE_ROW){
        msg->cert = strdup((const char*)sqlite3_column_text(statement, 0));
        msg->certLen = strlen(msg->cert)+1;
    }
    
    cleanup:
    sqlite3_finalize(statement);
    sqlite3_free(query);

    return retvalue;
}

// Helper function to add message to the messages table (used by both types of message)
int db_add_message(struct db_state* state, const struct api_msg* msg, int uid){
char* query = NULL;
    sqlite3_stmt* stmt = NULL;
    int res;

    // Add to message DB
    query = sqlite3_mprintf("INSERT INTO messages (sender, signature) VALUES (%i, @signature);", uid);
    SQL_CALL(sqlite3_prepare_v2(state->db, query, -1, &stmt, NULL), state->db, ERR_SQL, res);
    SQL_CALL(sqlite3_bind_blob(stmt, 1, msg->pub_msg.signature, MAX_ENCRYPT_LEN, NULL), state->db, ERR_SQL, res);

    res = sqlite3_step(stmt);

    cleanup:
    sqlite3_free(query);
    sqlite3_finalize(stmt);

    if(res != SQLITE_DONE) res = ERR_SQL;
    else res = SQLITE_OK;

    return res;
}

int db_add_pub_message(struct db_state* state, const struct api_msg* msg, int uid){
    if(msg->type != PUB_MSG) return ERR_INVALID_API_MSG;
    
    char* query = NULL;
    int res;

    SQL_CALL(db_add_message(state, msg, uid), state->db, ERR_SQL, res);

    query = sqlite3_mprintf("INSERT INTO pub_messages (id, msg) VALUES (last_insert_rowid(), %Q);", msg->pub_msg.msg);
    res = sql_exec(state->db, query, NULL, NULL);

    cleanup:
    sqlite3_free(query);
    
    return res == SQLITE_OK ? 0 : ERR_SQL;
}

int db_add_priv_message(struct db_state* state, const struct api_msg* msg, int uid){
    if(msg->type != PRIV_MSG) return ERR_INVALID_API_MSG;

    int id = nametoid(state, msg->priv_msg.to);
    // If error
    if(id == ERR_NO_USER) return ERR_RECIPIENT_INVALID;
    if(id < 0) return id;

    char* query = NULL;
    sqlite3_stmt* stmt = NULL;
    int res;

    SQL_CALL(db_add_message(state, msg, uid), state->db, ERR_SQL, res);

    query = sqlite3_mprintf("INSERT INTO priv_messages (id, recipient, sendermsg, recipientmsg) VALUES (last_insert_rowid(), %i, @sendermsg, @recipientmsg);", id);

    SQL_CALL(sqlite3_prepare_v2(state->db, query, -1, &stmt, NULL), state->db, ERR_SQL, res);
    SQL_CALL(sqlite3_bind_blob(stmt, 1, msg->priv_msg.frommsg, MAX_ENCRYPT_LEN, NULL), state->db, ERR_SQL, res);
    SQL_CALL(sqlite3_bind_blob(stmt, 2, msg->priv_msg.tomsg, MAX_ENCRYPT_LEN, NULL), state->db, ERR_SQL, res);

    res = sqlite3_step(stmt);

    if(res != SQLITE_DONE) res = ERR_SQL;
    else res = 0;

    cleanup:
    sqlite3_free(query);
    sqlite3_finalize(stmt);
    
    return res == SQLITE_OK ? 0 : ERR_SQL;
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

int db_register(struct db_state* state, const struct api_msg* msg){
    if(msg->type != REG) return ERR_INVALID_API_MSG;
    if(msg->encPrivKey == NULL || msg->cert == NULL) return ERR_INVALID_API_MSG;
    
    char* query = sqlite3_mprintf("INSERT INTO users (username, password, privkey, cert) VALUES(%Q, %Q, @privkey, %Q);", msg->reg.username, msg->reg.password, msg->cert);

    sqlite3_stmt* stmt;

    int res; 
    
    SQL_CALL(sqlite3_prepare_v2(state->db, query, -1, &stmt, NULL), state->db, ERR_SQL, res);
    SQL_CALL(sqlite3_bind_blob(stmt, 1, msg->encPrivKey, msg->encPrivKeyLen, NULL), state->db, ERR_SQL, res);

    res = sqlite3_step(stmt);

    if(res == SQLITE_CONSTRAINT_UNIQUE) res = ERR_USERNAME_EXISTS;
    else if(res != SQLITE_DONE) res = ERR_SQL;
    else res = nametoid(state, msg->reg.username);


    cleanup:
    sqlite3_finalize(stmt);
    sqlite3_free(query);

    return res;
}

int db_login(struct db_state* state, const struct api_msg* msg){
    if(msg->type != LOGIN) return ERR_INVALID_API_MSG;

    return verify_login(state, msg->login.username, msg->login.password);
}

void db_state_free(struct db_state* state){
    sqlite3_close(state->db);
}

