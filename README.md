
# General Overview
## File structure
The following list should be helpful to discern what each file is responsible for at a glance

### Server

|   File Name               | Purpose                                                           |
|---------------------------|-------------------------------------------------------------------|
| server.c                  | The main server file, accepts connections and spawns workers      |
| db.c/h                    | API for dealing with the database                                 |
| apicallbacks.h            | Definitions for the protocol api callbacks                        |
| protocols/prot_*          | Protocol API callback implementations (ex. prot_client.h/c)       |
| webserver/httputil.h/c    | Helper functions for the HTTP protocol                            |
| webserver/websockets.h/c  | Helper functions for the websockets protocol                      |
| webserver/route.h/c       | Implementation for the webserver routing (which URIs do what)     |
| worker/worker.h/c         | The main worker driver, contains functions to spawn the worker    |
| worker/workerapi.h/c      | The protocol agnostic server logic that handles client requests   |


### Other

|   File Name               | Purpose                                                           |
|---------------------------|-------------------------------------------------------------------|
| client.c                  | The client file                                                   |
| ui.h/c                    | Gets and processes user input, called by the client               |
| api.h/c                   | The common structs / functions used by both server / client       |
| crypto.h/c                | Functions to handle cryptography                                  |
| linkedlist.h/c            | Linked list functions                                             |
| util.h/c                  | General utility functins                                          |

## Communication
The server and native (non-web) client deals with api_msgs, which come in different types and contains all the information for a request / response (messages for example). The client and server  communicate by sending/recieving the api_msg instance directly over sockets. The type is indicated by an enum (msg_type_t), and indicate different structs in a union within an api_msg object that has been filled out.

The following list shows all the different api_msg types, and the information they contain.

#### none
Never actually sent, just a standin for no message

#### status
The message conveys some informational message, stores that message. (server->client)

#### error
The message has an errcode field containing an errorcode sent by the server. Error codes are defined in errcodes.h  (server->client)

#### priv_msg
The message represents a private message between two users. It contains a unix timestamp, two RSA public key encrypted messages (one for sender, one for recipient), and two unencrypted fields with the usernames of the sender and the recipient. RSA signed by sender. 

The "from" field is filled out by the server, not the client. When the server sends the apimessage, only the "frommsg" field is populated, since the client only needs one of the messages (the other is unreadable anyway).

#### pub_msg
The message represents a public message to everyone. It contains a unix timestamp, the (unencrypted) message, a field with the senders username, and is RSA signed by the sender.

The "from" field is filled out by the server, not the client.

#### who
The message contains a string with a list of all users. The string is only populated when sending from server->client, since the other direction is a request.

#### login / register
The message contains a username and hashed password. The registration additionally contains the certificate and private key (see: additional data)

#### login acknowledgement
The message acknowledges a successful login from the server. Contains certificate and private key (see: additional data)

#### exit
No fields

#### Key
A request for another users public key, or a response of the public key. Contains certificate if it's a response (see: additional data)

### Additional Data
The fields for each message type is stored in a union, so an entire api_msg is the size of the maximum possible message type. In addition to this, api_msgs contain lengths for an optional encrypted private key and/or a certificate that is attached to the message. This data is usually thousands of bytes long, so it would be inefficient to transmit it for every message. The server / client only reads the extra data if the recieved message has the lengths set.

There are three situations where this data is sent, the first is when a user registers/logs in, their (encrypted) private key and public key is sent to/from the server. The second is a key request, where the client (who presumably wants to send a private message) asks for a users certificate to encrypt the private message for the other user. The last situation is where the server sends a public or private message to a client, where it attatches the certificate of the message sender so the client can verify the message (using the TTPs public key). This will only be done once per sender, it is assumed the client stores the certificate for future use.

### Handling
Depending on the message recieved, and if it is server or clientside, the message is handled differently. A who message recieved by the server is treated as a request, and a who message is sent back with the string field filled in. The client will then handle it by printing the string. The various handlers in ui.c create messages from user input, called on in the function client_process_command (client.c). The server handles all messages in execute_request (worker.c). The client handles all messages from the server in execute_request (client.c).

# Security

## Measures

### Code Safety
No unsafe functions were used without explicitly sanitising fields. For example, strnlen is used instead of strlen, unless the variable was created locally (user input, disk reads) or sanitized. Most of the time safe calls are used even with sanitized inputs. Database calls either use bind or the sqlite3_printf "%Q" tag for strings, preventing SQL escaping.

## Notes
The username is used as the IV for the AES encrypted private key. It was our understanding that the IV could be public safely.
The username is also used as the salt. A random string would've been better, but this still prevents rainbow tables.

## Security Properties

TLS between client and server is used providing defence against basic man in the middle attacks or just simply sending a spoofed message. The list below will not mention this fact since it's trivial, and will instead discuss measures against more sophisticated attacks.

### Mallory cannot get information about private messages for which she is not either the sender or the intended recipient.
This is done by encrypting private messages end-to-end. The server stores encrypted messages which can only be read if you have the private key from the sender or the recipient. As Mallory does not have them she cannot read them.

### Mallory cannot send messages on behalf of another user.
Every message is signed by the sender, and verified with a users certificate. The certificate is signed from the CA. Whenever we receive a message we verify that the certificate is correct and belongs to the person who actually sent the message, and that the signature is correct. Since Mallory cannot forge the signature, we can be sure that the message is sent from who it says it is.

### Mallory cannot modify messages sent by other users.
Again this comes down to the signing. If even only a single character gets changed the hash of the message will not be the same and the signature will not be correct. Thus if Mallory were to change the message the client would know the message got changed and will warn the user by printing "Unsigned!" before the message.

### Mallory cannot find out users’ passwords, private keys, or private messages (even if the server is compromised).
The database only stores hashed passwords. Even if the server is compromised Mallory cannot do much with this information as Mallory cannot undo the hash. Private keys are stored encrypted with the password using AES. Assuming that the password is indeed safe there is no way for Mallory to decrypt the private key. Then assumming that both the password and the private key are safe Mallory cannot decrypt the private messages as it does not have the private key. Note: the private keys could be brute forced if the user sets a bad password.

### Mallory cannot use the client or server programs to achieve privilege escalation on the systems they are running on.
### Mallory cannot leak or corrupt data in the client or server programs.
Well assuming that Mallory can compromise the server she actually could corrupt the data. However because of the signature the user/client would know that the data has been corrupted. The best effort was made to prevent any buffer overflows and we believe there shouldn't be a way to gain access to the systems through this program.

### Mallory cannot crash the client or server programs.
The best effort was made to prevent buffer overflows. Aside from big DDOS attacks, it should be safe.

### The programs must never expose any information from the systems they run on, beyond what is required for the program to meet the requirements in the assignments.
The best effort was made to prevent buffer overflows. Besides this, amd aside from side-channels, it should not be possible to discern system information with the program.

### The programs must be unable to modify any files except for chat.db and the contents of the clientkeys and clientkeys directories, or any operating system settings, even if Mallory attempts to force it to do so. 
The program only ever accesses the database (on the server) or their key directories, no other access is used.

## possible attacks and their defenses

### Man-in-the-middle
TLS is used, the man in the middle could not spoof the initial handshake and the rest is protected. Hypothetically, even if someone got in the middle, All messages are signed by the private key, which can only be accessed with the users password, so getting in the middle wouldn't even get you much.

### Buffer overflows
Safe functions are used instead of their unsafe versions (strnlen vs strlen), unless the outputs were garunteed to be safe (come from a library and independent from networked input, db calls, file reads etc.).

### Injection
 Besides the aformentioned buffer overflow checks, we make sure any SQL input in message from the client are properly sanitised.

### Padding oracle attack
The defense of this attack is handled by openSSL. No AES decryption happens from the server so it's impossible to gain access to AES information from there.


# Client details
## client initialization 
When we initialize the client we connect to the server and check the server's certificate. If everything is fine we start the ssl handsake. When initializing we also create two linked lists. One we use to store certificates from other users. The other is used as a queue to temporarily store private messages we don't have keys to encrypt yet.

## parsing input (client_process_command, client.c)
The client starts with seperating the command from the message in "client_process_command". The command and message gets stored in their respective struct within the api_message. If the message is too long, the command is invalid or the amount of arguments is invalid we give an error and ask them to try again. Depending on the command a handler function is then called. 

## preparing message
Depending on the command different steps are taken.

-   ### register (input_handle_register| ui.c)    
    When register is we first check if the password and/or the username is valid (not empty). We hash the password with the username as salt, generate a private/public key pair and request a certificate from the CA. This private key is then encrypted using the password. The hashed password, the certificate and the encrypted private key are then ready to be send to the server. This is so that whenever the user logs in from a different device they can retrieve their own keys from the server (Apparently this was not necessary as the professor indicated later that we could assume the user manually copies over their keys but we already implemented it, it's also a pretty neat solution, albeit less secure). If the username was already taken the server asks the user to use a different username.

-   ### login  (input_handle_login| ui.c)  
    After login is called we hash the password with the username as salt and send it with the username to the server. If the combination is valid we receive our certificate and encrypted private key back from the server. We decrypt the private key with our password and then encrypt and decrypt a test string to verify the keys. This ensures that we have the same keypair every time even when logging in from different devices, and makes sure the server isn't sending us a fake keypair with a known private key. (loginAck| client.c) 
    
-   ### private message (input_handle_privmsg| ui.c)
    To send a private message we have to get the public key of the receipient so we can encrypt the message (using RSA). This limits the message length, but we had a 160 byte message length limit anyway. We first look through local key cache. If the key is not found in the linked list we request the key from the server and put the to be transmitted message in a queue (linked list) so we can send the message whenever we receive the key. When we receive the key (execute_request, handle_key| client.c) the authenticity of the certificate is verified. The key is then added to the key cache and we go through the queue to see if there is a message we can send now with the key. Regardless of whether we already had the key or just got the key from the server we sign the message (hash and encrypt with our private key), encrypt a copy of the message with the recipients public key and a copy of the message with our own public key. These messages and the signature are then send to the server. 

-   ### public message (input_handle_pubmsg| ui.c)
    When sending a public message we use RSA digital signatures to make sure that what we send is not tampered with during transmission. We first compute the hash of the message and encrypt it with the sender's (our own) private key. Then we send the encrypted hash and the message over the wire where the receiving end computes the hash of the message and verifies the message by decrypting the signature using the senders public key. If not already sent, the server adds the certificate of the sender to the message and after checking for validity the recipient can extract the key. If the computed hash and the decryption of the signature are equal then the signature is correct and the message has not been tampered with.

-   ### users 
    No cryptography happens for the user call, we just set the message type and send it.

-   ### exit 
    No cryptography happens for the exit call either, we just set the message type and send it.

# Server Details
## server and worker
The server creates a worker process (if the limit has not been reached) on the inital connection. The worker will then check if the user is logged in and authenticate and verify any requests incoming. The checks ensure the safety of the message and is disccussed later. After the checks the worker thread will execute the command in "execute_request"(worker.c). Here, depending on the command, the worker makes the appropriate database calls (db.c). The user assigned to each worker is kept track with a block of shared memory, which the workers accesses when building the response to a /users command.

## wrapping up
If a message was recieved, the worker notifies the server which notifies the other workers. The worker is responsible for sending back appropriate messages to the clients. In "execute_request"(client.c) the client, depending on the message type then decrypts and displays the correct message. Keys are handled differently as described in public and private messaging.   

## Worker API

Originally, the implementation was that the client sent the bytes of a local api_msg to the server, and vice versa. This worked well with just the native client, but when adding the HTTP protocol this was insufficient, as the server was quite rigid in only accepting api_msgs over the socket. To solve this, the server implementation was split into two parts: the _protocols_ and the _worker api_, instead of just having the worker. 

With this, the main server logic (the worker api) is designed to be protocol agnostic. The code to interact with api_msg's is defined in workerapi.h. The different _protocols_ (in the directory protocols/) handle interfacing with the different types of connections, forming api_msgs out of them and giving it to the worker_api to handle. Instead of the worker directly sending/recieving from sockets like before, The worker API interacts with protocol-specific function callbacks to send / recieve api_msgs (apicallbacks.h). This forms a sort of stack, with the lower transport-like layer dealing with protocol-based communications (ex. native/websockets), and the upper layer dealing with the actual requests, including forming api_msgs for the lower layer to send. The server spawns the appropriate worker to deal with different protocols depending on how a connetion is established (server.c:handle_incoming). This also allows workers to dynamically change protocols. For example, the http protocol implementation replaces itself with the websocket api callbacks, passing control to the websocket protocol implementation.

This was done for the bonus HTTP assignment, to allow for the different protocol in a clean way, but in theory this means the application should be easily expandable to other protocols such as IRC.

                                                    ---------------
                                                    |     db      |
                                                    ---------------
                                                    |  workerapi  |
                            ----------   spawns     --------------- V^ send, recv
                            | server | -----------> |  http | api | 
                            ----------   worker     ---------------
                                                    |     SSL     |
                                                    ----|-----|----
                                                        V     V  TCP
                                                    ---------------
                                                    |browsr|client|
                                                    ---------------

# Bonus
A webclient was implemented for this assignment. This is off by default, but if a second argument is present when running the server, it will be ran on port 443 (default for HTTPS). It can be accessed at https://localhost/ (*ON FIREFOX*, as per the assignemnent. Chrome doesn't work for some reason). Opening 443 requires the program to be ran with sudo, although the port can be changed in the initialization of server.c. Implemented is a basic webserver which serves web pages in the www/ directory. Routes and HTTP handling are setup in prot_http.c and route.h. POST requests were also implemented but are not used in favour of websockets, which are implemented in prot_wb.c. The connection is made and the javascript logic upgrades the connection to websockets, which is used to talk to the server.
The web interface itself is a bit janky, since CSS is not fun, but it is functionally OK. All security measures the native client has have also been implemented in the web client (with the exception of TLS certificate verificaiton, since that is handled by the browser).

## PLEASE NOTE
1. The web client gets the TTP certificate from the server via HTTP request, this is obviously unsafe, and could be forged by the server. In a real situation the CA would be a real one that systems have access to anyway. This only affects verifying the certificates other users (which does have implications for the other security measures), but I could not think of a proper way to distribute this certificate to the webclient, but since the native client is assumed to have safe access to it, I assumed that serving it from the server would also be an OK shortcut, and it could be assumed that the server is unable to forge the CA for whatever reason.
2. Registration is not possible using the web interface; One must log in with a user created from the CLI. This is because registration requires the generation of an RSA key pair and the signing from the TTP, and from a web interface there is no simple way to access the ttp script.

## Implementation
The serverside websockets protocol implementation encodes outgoing messages in JSON, sending it to the web client. The web client sends direct bytes, which are read into an api_msg. The difference in the ways messages are conveyed is because formatting json is much easier than parsing it. The rest is the same on the serverside, as the websocket protocol implementation translates incoming messages to api_msgs that the worker api can handle.

## Full steps to see the web page
1. Run the server with (any) third argument, with the second argument indicating the port for the CLI client: `sudo ./server 2345 Y`
2. Create an account in the CLI (connecting as usual): `/register username password`
3. Open the URL in firefox (tested on the latest version, fresh install/no extensions or settings changed) `https://localhost`
4. Since the certificate was signed by a made-up CA, you will have to click past the warning screen

## Security considerations
Javascript is much easier to program for security, since you can't buffer overflow. The worse than can happen is an error message and some function doesn't work properly. However, there were additional challenges invovled when talking about data representation. Since the javascript recieves json, it was possible to send messages with characters such as " to escape from the json. The solution to this was to encode everything in base64.
