# walkthrough

## client initialization 
When we initialize the client we connect to the server and check the server's certificate. If everything is fine we start the ssl handsake. When initializing we also create two linked lists. One we use to store certificates from other clients to look up public keys for when we are private messaging them or decrypting public messages. The other is used as a queue to temporarily store the private message we were about to send but for which we do not have the recipients certificate yet. A special KEY request is then send to the server which will provide us with the certificate of the user we want to privately communicate with.

## parsing input (client_process_command, client.c)
The client starts with seperating the command from the message in "client_process_command". The command and message gets stored in their respective struct within the api_message. If the message is too long, the command is invalid or the amount of arguments is invalid we give an error and ask them to try again. Depending on the command a handler function is then called. 

## preparing message
Depending on the command different steps are taken.

-   ### register (input_handle_register| ui.c)    
    When register is we first check if the password and/or the username is valid (not empty). We hash the password with the username as salt, generate a private/public key pair and request a certificate from the CA. This private key is then encrypted using the password. The hashed password, the certificate and the encrypted private key are then ready to be send to the server. This is so that whenever the user logs in from a different device they can retrieve their own keys from the server. If the username was already taken we ask the user to use a different username. (Apparently this was not necessary as the professor indicated later that we could assume the user manually copies over their keys but we already implemented it so whatever.) 

-   ### login  (input_handle_login| ui.c)  
    After login is called we hash the password with the username as salt and send it with the username to the server. If the combination is valid we receive our certificate and encrypted private key back from the server. We decrypt the private key with our password and then encrypt and decrypt a test string to verify the keys. This ensures that we have the same keypair every time even when logging in from different devices. (loginAck| client.c) 
    
-   ### private message (input_handle_privmsg| ui.c)
    To send a private message we have to get the public key of the receipient so we can encrypt the message (using RSA). We first look through our linked list containing keys. If the key is not found in the linked list we request the key from the server and put the to be transmitted message in a queue (linked list) so we can send the message whenever we receive the key. When we receive the key (execute_request, handle_key| client.c) the authenticity of the certificate is verified. The key is then added to the list of keys and we go through the queue to see if there is a request we can fullfil now with the key. Continuing this, regardless of whether we already had the key or just got the key from the server we sign the message(hash and encrypt with our private key), encrypt a copy of the message with the recipients public key and a copy of the message with our own public key. These messages and the signature are then send to the server. 

-   ### public message (input_handle_pubmsg| ui.c)
    When sending a public message we use RSA digital signatures to make sure that what we send is not tampered with during transmission. We first compute the hash of the message and sign it with the sender's (our own) private key. Then we send the encrypted hash and the message over the wire where the receiving end computes the hash of the message and verifies the message by decrypting the signature using the senders public key. The server adds the certificate of the sender to the message and after checking for validity the recipient can extract the key. If the computed hash and the decryption of the signature are equal then the signature is correct and the message has not been tampered with.

-   ### users 
    No cryptography happens for the user call, we just set the message type and send it.

-   ### exit 
    No cryptography happens for the exit call either, we just set the message type and send it.

## server and worker
The server creates a worker process (if the limit has not been reached) on the inital connection. The worker will then check if the user is logged in and authenticate and verify the request. After the checks the worker thread will execute the command in "execute_request"(worker.c). Here, depending on the command, the worker makes the appropriate database calls (db.c). The user assigned to each worker is kept track with a block of shared memory, which the workers accesses when building the response to a /users command.

### Worker API
The server is designed to be protocol agnostic. The API to interact with the data is defined in workerapi.h. Files in the directory protocols/ handles interfacing with the different connections. The worker API interacts with function callbacks for send/recv/notify that are set depending on the protocol. This forms a sort of stack, with the lower transport-like layer dealing with protocol-based communications (ex. http or the client api), and the upper layer dealing with the actual requests, including forming api_msgs for the lower layer to send. The server spawns the appropriate worker to deal with different protocols depending on how a connetion is established. This also allows workers to change how they should handle requests. For example, the http api calls replace themselves with websocket api calls 

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
If a message was recieved, the worker notifies the server which notifies the other workers. The worker is responsible for sending back appropriate messages to the clients. In "execute_request"(client.c) the client, depending on the message type then decrypts and displays the correct message. Keys are handled differently as described in public and private messaging.   

# messages
## message types
Messages contain a union that is composed of a struct for each message type with the appropriate fields for that message. Messages are built in ui.c handler functions, or in worker.c for the serverside.
### status
The message has a statusmsg field containing a string sent by the server.
### error
The message has an errcode field containing an errorcode sent by the server. This is processed by the client in the function error (client.c) where the appropriate error message is printed. Error codes are defined in errcodes.h 
### priv_msg
The message has a timestamp (unix), a from message field (encrypted with the senders public key), a from field, a to message field (encrypted with the recipients public key), a to field and a signature field(hashed and then signed with private key). 
### pub_msg
Identical to priv_msg without a to field and only containing one message (unencrypted), the signature field is also hashed and signed with a private key to ensure that the message is from the actual sender and has not been tampered with.
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
The entire attack surface was limited to the initial call to verify_request; when the packet leaves this function, it has the proverbial stamp of approval. However, each module is designed to be self sufficient, so the message will be further checked with calls to the database API, to ensure, for example, that the registration handler isn't handling a login message. The strings are also assumed to be malformed, and null termination is explicity set to avoid overflowing into the database, this is despite the fact that null termination is explicitly checked for in the verify_request function.

## request verification
The verify-request function double checks if a request if safe.

### request authentication TODO: ?

### sanity check
The struct needs to be as safe as we created it ourselves, so null termination of strings is checked. since the struct is a union, a lot of the checks are code-duplicated, but keeping the checks seperate encourages explicit checks for other factors if needed.

# client
## message validity
When parsing the input we check if the the command is valid, and the message is not too long. We also check if the amount of parameters given are correct and if they are not too long.

## cryptography

### message encryption TODO: we discard the message if signature is invalid right
All messages have a signature which consists of the hashed message which is encrypted with the senders private key. Private messages are send to the server in twofold where one of the messages is encrypted with our own public key and one message is encrypted with the recipients public key. This ensures that all messages are end-to-end encrypted as they are stored encrypted in the server and the server does not have the private key to decrypt them. When receiving messages the client always checks if the signature is valid with help of the certificate which the client also verifies. If the signature is invalid we discard the message.

## displaying messages
When displaying the messages we make sure to never print more characters than the respective max length.

# database
## message containing sql commands
The database api makes sure that an sql command in the message wont affect any database. This is handled by the sqlite3 library mprintf call with the %Q format specifier, which quotes any input and escapes any internal quotes, ensuring escape impossible.

## security properties

### Mallory cannot get information about private messages for which she is not either the sender or the intended recipient.
This is done by encrypting private messages end-to-end. The server stores encrypted messages which can only be read if you have the private key from the sender or the recipient. As Mallory does not have them she cannot read them.

### Mallory cannot send messages on behalf of another user. TODO: add some more maybe?
Every message is signed and contains a certificate with the public key to decrypt it. The certificate is requested from the CA which we assume is trustworthy. Whenever we receive a message we verify that the certificate is correct and belongs to the person who actually sent the message. We then hash the message and compare it to the decryption of the encrypted hash (the signature). Since Mallory cannot forge such a valid certificate we can be sure that the actual sender is who they say they are.

### Mallory cannot modify messages sent by other users. TODO: if the message got tampered with do we still show it?
Again this comes down to the signing. If even only a single character gets changed the hash of the message will not be the same and the signature will not be correct. Thus if Mallory were to change the message the client would know the message got changed and would not show it.

### Mallory cannot find out users’ passwords, private keys, or private messages (even if the server is compromised).
The database only stores hashed salted passwords. Even if the server is compromised Mallory cannot do much with this information as Mallory cannot undo the hash. Frequency analysis is also not possible due to the salt. Private keys are stored encrypted with the password. Assuming that the password is indeed safe there is no way for Mallory to decrypt the private key. Then assumming that both the password and the private key are safe Mallory cannot decrypt the private messages as it does not have the private key.

### Mallory cannot use the client or server programs to achieve privilege escalation on the systems they are running on. TODO: not sure how we actually do this

### Mallory cannot leak or corrupt data in the client or server programs. TODO: is this an actual good answer?
Well assuming that Mallory can compromise the server she actually could corrupt the data. However because of the signature the user/client would know that the data has been corrupted.  

### Mallory cannot crash the client or server programs. TODO: do we have anything in place to prevent the client from crashing?
The server has a maximum number of clients it supports at a time making it hard for Mallory to overwork the server by connnecting lots of clients. 

### The programs must never expose any information from the systems they run on, beyond what is required for the program to meet the requirements in the assignments. TODO: actual answer

### The programs must be unable to modify any files except for chat.db and the contents of the clientkeys and clientkeys directories, or any operating system settings, even if Mallory attempts to force it to do so.  TODO: do we have anything in place for this?


## possible attacks and their defenses

### Man-in-the-middle
Our clients and server exchange certificates issued by the CA which is used to authenticate messages send by the owner of that certificate. An invalid certificate will not be accepted and we can therefore identify this type of attack. Also even if there were to be a man in the middle all the private information (passwords, private messages) are encrypted/hashed and thus useless if intercepted.

### Buffer overflows
When handling input from a user we have several security checks in place which make sure the input does not exceed certain bounderies that could trigger potential buffer overflows. Input checks include but are not limited to: the amount, length, empty and type of arguments to make sure the input of the client is valid.

### Injection
 Besides the aformentioned buffer overflow checks, we make sure any SQL input in message from the client are not executed during database handling. (See database section)

### Padding oracle attack
The defense of this attack is handled by openSSL and achieved through random padding.
