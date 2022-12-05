# General Overview
## File structure
The following list should be helpful to discern what each file is responsible for at a glance

### Server
|   File Name               | Purpose                                                           |
-------------------------------------------------------------------------------------------------
| server.c                  | The main server file, accepts connections and spawns workers      |
| db.c/h                    | API for dealing with the database                                 |
| apicallbacks.h            | Definitions for the protocol api callbacks                        |
| protocols/prot_*          | Protocol API callback implementations (ex. prot_client.h/c)       |
| webserver/httputil.h/c    | Helper functions for the HTTP protocol                            |
| webserver/route.h/c       | Implementation for the webserver routing (which URIs do what)     |
| worker/worker.h/c         | The main worker driver, contains functions to spawn the worker    |
| worker/workerapi.h/c      | The protocol agnostic server logic that handles client requests   |


### Other
|   File Name               | Purpose                                                           |
-------------------------------------------------------------------------------------------------
| client.c                  | The client file                                                   |
| ui.h/c                    | Gets and processes user input, called by the client               |
| api.h/c                   | The common structs / functions used by both server / client       |
| crypto.h/c                | Functions to handle cryptography                                  |
| linkedlist.h/c            | Linked list functions                                             |
| util.h/c                  | General utility functins                                          |

## Communication
The server and native (non-web) client deals with api_msgs, which come in different types and contains all the infromation for a request / response (messages for example). The client and server  communicate by sending/recieving the api_msg instance directly over sockets. 


The following list shows all the different api_msg types, and the information they contain.

#### none
Never actually sent, just a standin for no message

#### status
The message conveys some informational message, stores that message.

#### error
The message has an errcode field containing an errorcode sent by the server. Error codes are defined in errcodes.h 

#### priv_msg
The message represents a private message between two users. It contains a unix timestamp, two RSA public key encrypted messages (one for sender, one for recipient), and two unencrypted fields with the usernames of the sender and the recipient. RSA signed by sender

#### pub_msg
The message represents a public message to everyone. It contains a unix timestamp, the (unencrypted) message, a field with the senders username, and is RSA signed by the sender.

#### who
The message contains a string with a list of all users. 

#### login / register
The message contains a username and hashed password.

#### login acknowledgement
The message acknowledges a successful login from the server.

#### exit
No fields

#### Key
A request for another users public key, or a response of the public key.

### Additional Data
The fields for each message type is stored in a union, so an entire api_msg is the size of the maximum possible message type. In addition to this, api_msgs contain lengths for an optional key or certificate that is attached to the message. This data is usually thousands of bytes long, so it would be inefficient to transmit it as part of the main message, so the server / client only reads the extra data if the recieved message has the lengths set.

There are three situations where this data is sent, the first is when a user logs in, their (encrypted) private key and public key is sent. The second is a key request, where the client (who presumably wants to send a private message) asks for a users certificate to encrypt the private message for the other user. The last situation is where the server sends a public message to a client, it attatches the certificate of the message sender so the client can verify the message. This will only be done once per sender, it is assumed the client stores the certificate for future use.

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

# Server Details

## server and worker
The server creates a worker process (if the limit has not been reached) on the inital connection. The worker will then check if the user is logged in and authenticate and verify the request. After the checks the worker thread will execute the command in "execute_request"(worker.c). Here, depending on the command, the worker makes the appropriate database calls (db.c). The user assigned to each worker is kept track with a block of shared memory, which the workers accesses when building the response to a /users command.

## wrapping up
If a message was recieved, the worker notifies the server which notifies the other workers. The worker is responsible for sending back appropriate messages to the clients. In "execute_request"(client.c) the client, depending on the message type then decrypts and displays the correct message. Keys are handled differently as described in public and private messaging.   

## Worker API
The native client/server send api_msgs directly through sockets, with http/websockets implemented as a serverside translation layer between the native protocol and other protocols. For example, the websocket protocol (prot_wb.h) translates websocket frames into native API msgs (defiend in api.h), that the server worker api can handle. It also translates outgoing api_msgs from the worker api to websocket frames / json, which the web app can handle. 

With this, the server is designed to be protocol agnostic. The code to interact with requests is defined in workerapi.h. Files in the directory protocols/ handles interfacing with the different types of connection. The worker API interacts with function callbacks for send/recv that are set depending on the protocol. This forms a sort of stack, with the lower transport-like layer dealing with protocol-based communications (ex. http/client api/websockets), and the upper layer dealing with the actual requests, including forming api_msgs for the lower layer to send. The server spawns the appropriate worker to deal with different protocols depending on how a connetion is established. This also allows workers to change how they should handle requests. For example, the http protocol api replaces itself with the websocket api callbacks. 

This was done for the bonus assignment, to allow for the different protocol in a clean way, but in theory this means the application should be easily expandable to other protocols such as IRC.

                                                    ---------------
                                                    |     db      |
                                                    ---------------
                                                    |  workerapi  |
                            ----------   spawns     --------------- -> send, recv
                            | server | -----------> |  http | api | 
                            ----------   worker     ---------------
                                                    |     SSL     |
                                                    ----|-----|----
                                                        V     V  TCP
                                                    ---------------
                                                    |browsr|client|
                                                    ---------------



# Bonus
A webclient was implemented for this assignment. This is off by default, but if a second argument is present when running the server, it will be ran on port 443 (default for HTTPS). It can be accessed at https://localhost/ (*ON FIREFOX*, as per assignemnent. Chrome doesn't work for some reason). Opening 443 requires the program to be ran with sudo, although the port can be changed in server.c. Implemented is a basic webserver which serves web pages in the www/ directory. Routes and HTTP handling are setup in prot_http.c. POST requests were also implemented but are not used in favour of websockets, which are implemented in prot_wb.c. The connection is made and the javascript logic upgrades the connection to websockets, which is used to talk to the server.

The web interface itself is a bit janky, since CSS is not fun, but it is functionally OK. All security measures the native client has have also been implemented in the web client (with the exception of TLS certificate verificaiton, since that is handled by the browser).

## PLEASE NOTE
1. The web client gets the TTP certificate from the server via HTTP request, this is obviously unsafe, and could be forged by the server. In a real situation the CA would be a real one that systems have access to anyway. This only affects verifying the certificates other users (which does have implications for the other security measures), but I could not think of a proper way to distribute this certificate to the webclient, but since the native client is assumed to have safe access to it, I assumed that serving it from the server would also be an OK shortcut, and it could be assumed that the server is unable to forge the CA for whatever reason.
2. Registration is not possible using the web interface, one must log in with a user created from the CLI. This is because registration requires the generation of an RSA key pair and the signing from the TTP, and from a web interface there is no simple way to access the ttp script.