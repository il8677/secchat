# walkthrough
## parsing input
The client starts with seperating the command from the message in "client_process_command". The command and message gets stored in their respective struct within the api_message. If the message is too long or the command is invalid we give an error and ask them to try again. The structs are then sent to the socket.

## server and worker
The server creates a worker process (if the limit has not been reached) on the inital connection. The worker will then check if the user is logged in and authenticate and verify the request. After the checks the worker thread will execute the command in "execute_request"(worker.c). Here, depending on the command, the worker makes the appropriate database calls (db.c). The user assigned to each worker is kept track with a block of shared memory, which the workers accesses when building the response to a /users command.

### Worker API
The server is designed to be protocol agnostic. The API to interact with the data is defined in workerapi.h. Files in the directory protocols/ handles interfacing with the different connections. The worker API interacts with function callbacks for send/recv/notify that are set depending on the protocol. This forms a sort of stack, with the lower transport-like layer dealing with protocol-based communications (ex. http or the client api), and the upper layer dealing with the actual requests, including forming api_msgs for the lower layer to send. The server spawns the appropriate worker to deal with different protocols depending on how a connetion is established.

                                                    ---------------
                                                    |     db      |
                                                    ---------------
                                                    |  workerapi  |
                            ----------   spawns     --------------- -> send, recv, notify
                            | server | -----------> |  http | api | 
                            ----------   worker     ---------------
                                                    |     SSL     |
                                                    ----|-----|----
                                                        V     V  TCP
                                                    ---------------
                                                    |browsr|client|
                                                    ---------------

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
