# walkthrough
## parsing input
The client starts with seperating the command from the message in "client_process_command". The command and message gets stored in their respective struct. If the message is too long or the command is invalid we give an error and ask them to try again. The structs are then send to the socket.

## server and worker
The server then makes makes space for the child and wakes a worker thread (if the limit has not been reached). The worker will then check if the user is logged in and authenticate and verify the request. After the checks the worker thread will execute the command in "execute_request"(worker.c). Here, depending on the command the worker might access the respective databases to write things in them or read things from them. If the database does not exist yet we make one.

## wrapping up
The worker then notifies the server which then in turn sends the message back to the client. In "execute_request"(client.c) the client, depending on the message type then displays the correct message.   

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
The database api makes sure that an sql command in the message wont affect any database. This is handled by the sqlite3 library.