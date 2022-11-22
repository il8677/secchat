# walkthrough
## parsing input
The client starts with seperating the command from the message in "client_process_command". The parsed command stores the relevant information in the respective struct within the api_msg. If the message is too long or the command is invalid we give an error and ask them to try again. The structs are then sent through the socket.

## server and worker
The server creates a worker process (if the limit has not been reached) on the inital connection. The worker will then check if the user is logged in and authenticate and verify any requests incoming. The checks ensure the safety of the message and is disccussed later. After the checks the worker thread will execute the command in "execute_request"(worker.c). Here, depending on the command, the worker makes the appropriate database calls (db.c). The user assigned to each worker is kept track with a block of shared memory, which the workers accesses when building the response to a /users command.

## wrapping up
If a message was recieved, the worker notifies the server which notifies the other workers. The worker is responsible for sending back appropriate messages to the clients. In "execute_request"(client.c) the client, depending on the message type then displays the correct message.

# messages
## message types
Messages contain a union that is composed of a struct for each message type with the appropriate fields for that message. Messages are built in ui.c handler functions, or in worker.c for the serverside.
### status
The message has a statusmsg field containing a string sent by the server.
### error
The message has an errcode field containing an errorcode sent by the server. This is processed by the client in the function error (client.c) where the appropriate error message is printed. Error codes are defined in errcodes.h 
### priv_msg
The message hav a timestamp (unix), a msg field, a from field, and a to field. 
### pub_msg
Identical to priv_msg without a to field.
### who
The message contains a string with a list of all users. 
### login / register
The message contains a username and password (plaintext for now).

### exit
No fields

## Handling
Depending on the message recieved, and if it is server or clientside, the message is handled differently. A who message recieved by the server is treated as a request, and a who message is sent back with the string field filled in. The client will then handle it by printing the string. The various handlers in ui.c create messages from user input, called on in the function client_process_command (client.c). The server handles all messages in execute_request (worker.c). The client handles all messages from the server in execute_request (client.c).

# Encryption Model
## SSL
Every api_msg between the server and  client is encrypted using SSL. With certificates being signed by the TTP. After that, the SSL protocol entails a symmetric key to be shared for all future communications. Then, all future api_msgs are sent encrypted with the key determined by the ssl protocol. The certificate will be verified with the TTPs public key to ensure it is valid. It is assumed that the CA is not an attack vector and thus, this will verify the identity of the server.

## Passwords
In addition to the communication being encrypted. Passwords are never sent plaintext to the server, they are hashed (with a salt) client side. This way, if the server is compromised, mallory cannot see the password. 

## Private Messages
Private messages are also encrypted asymmetrically, two copies of the message encrypted by each side's public keys are stored. The private key is sent from the server to the client at login. The private key is encrypted and decrypted by the client using the password. This ensures the server cannot ever see the private key. The key pair is generated at registration and sent to the server (with the private key encrypted). The public key of other users can be requested by the clients from the server, and the TTP will verify the keys sent are authentic.

## Threat model
- Mallory cannot get information about private messages for which she is not either the sender or the intended recipient. 

The communication is encrypted with SSL, so nothing can be gained by intercepting the packets

- Mallory cannot send messages on behalf of another user
 
Since all communication is secured by SSL, Mallory would not be able to impersonate another client without connecting and logging in with the password. Public messages can be spoofed if mallory compromised the server, but that is not a required property / in the threat model.

- Mallory cannot modify messages sent by other users. 

Since all communication is secured by SSL (Which uses MAC to authenticate messages), Mallory would not be able to impersonate another client.

- Mallory cannot find out users’ passwords, private keys, or private messages (even if the server is compromised).

Stored passwords will be hashed using SHA-2, using salt to give a unique hash even if users have the same password to login. The private messages sent are encrypted asymetrically, with only the private key of the involved parties able to decrypt it, and the private key themselves being only decryptable with the users password, so even if mallory had access to the server she would not be able to see the private messages. Furthermore, she can’t man in the middle with a known private/public key pair because the TTP can verify the public keys sent really do belong to the user.


# server
## layered security
The entire attack surface was limited to the initial call to verify_request; when the packet leaves this function, it has the proverbial stamp of approval. However, each module is designed to be self sufficient, so the msg will be further checked with calls to the database API, to ensure, for example, that the registration handler isn't handling a login message. The strings are also assumed to be malformed, and null termination is explicity set to avoid overflowing into the database, this is despite the fact that null termination is explicitly checked for in the verify_request function.

## request verification
The verify-request function double checks if a request if safe.
### request authentication

### sanity check
The struct needs to be as safe as we created it ourselves, so null termination of strings is checked. since the struct is a union, a lot of the checks are code-duplicated, but keeping the checks seperate encourages explicit checks for other factors if needed.

# client
## message validity
When parsing the input we check if the the command is valid, and the message is not too long. We also check if the amount of parameters given are correct and if they are not too long.

## displaying messages
When displaying the messages we make sure to never print more characters than the respective max length.

# database
## message containing sql commands
The database api makes sure that an sql command in the message wont affect any database. This is handled by the sqlite3 library mprintf call with the %Q format specifier, which quotes any input and escapes any internal quotes, ensuring escape impossible.
