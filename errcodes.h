#ifndef ERR_H
#define ERR_H

#define ERR_SQL -1 // Internal sql error
#define ERR_NAME_INVALID -2 // Name given by client is invalid
#define ERR_INVALID_API_MSG -3 // Internal server error
#define ERR_USERNAME_EXISTS -4 // Username already exists
#define ERR_INCORRECT_LOGIN -5 // Username/password wrong
#define ERR_AUTHENTICATION -6 // Message could not be authenticated
#define ERR_NO_USER -7 //Not logged in
#define ERR_LOGGED_IN -8

#define ERR_COMMAND_ERROR -11 //Command is not recognised
#define ERR_MESSAGE_INVALID -12 //Messsage given by client is invalid
#define ERR_MESSAGE_TOOLONG -13 //Message given by client is too long
#define ERR_PASSWORD_INVALID -14 //Password given by client is invalid
#define ERR_USERNAME_TOOLONG -15 //Given username is too long
#define ERR_PASSWORD_TOOLONG -16 //given password is too long
#define ERR_INVALID_NR_ARGS -17 //too many arguments were given

#endif