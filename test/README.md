# 
#  This file contains information about the Secure Programming automated
#  test script suite. I suggest you read it prior to testing your homework


## Important notes:
### 1. Each test will launch a server and 1 or multiple clients.
###
### 2. A test will check the stderr of all launched programs upon the completion
###    of the test and will report the test as failed in case any output is 
###    found in stderr. Make sure that your program writes all errors relevant
###    to the functional specifications of the chat app to stdout. When you'll
###    have to add end-to-end encryption take into consideration that openssl
###    routines may write their output to stderr. Be sure to redirect this
###    input to /dev/null if your calling openssl routines from your makefile.
###
### 3. Based on the command the client issues it will have to return some
###    predefined error/success messages (most of which are already given as 
###    an example in the assignment pdf) which will be presented in this 
###    document. You can find a dictionary (dubbed chat_messages) at the 
###    beginning of test.py file containing all of these messages.
###
### 4. For executing the basic tests (which in theory should all pass for 
###    deadline 1A) from the root of the test suite you must run the 
###    following command "python3 test.py /root/dir/of/your/chatapp"
###
### 5. For executing advanced tests (which should all pass for deadline 1C)
###    you must run the following command:
###   "python3 test.py /root/dir/of/your/chatapp advanced"


#### Predefined messages: all predefined messages are explained bellow.
##### 
##### "registration succeeded" should be outputed standalone on a newline if the 
#####  user successfully registers with a @username and @password.
##### 
##### "error: user erik already exists" should be outputed standalone on a newline 
#####  if we cannot register user @erik as he was already registered.
##### 
##### "authentication succeeded" should be outputed standalone on a newline if the 
#####  user successfully logins with a @username and @password.
##### 
##### "error: invalid credentials" should be outputed standalone on a newline if the 
#####  user cannot login due to invalid credentials.
#####
##### "error: unknown command /command" should be outputed standalone on a newline 
##### if the user types in a @command not included in the assignment sheet.
#####
##### "error: invalid command format" should be outputed standalone on a newline 
##### if the user types in an existing command without adhering to the syntax 
##### specified in the assignment sheet.
#####
##### "error: user not found" should be outputed standalone on a newline 
##### if we try to send a private message to an unregistered user.
#####
##### "error: command not currently available" should be outputed standalone 
##### on a newline if user types in a command that shouldn't be available while
##### the user is logged in/unlogged in.
#####
##### Notes: 1. all the success/error messages should be outputed to stdout.
#####        2. you can output any other additional messages in your app provided
#####           you also output the error/success message presented above 
#####           accordingly.
#####        3. we will also manually verify your homeworks so do not try to game
#####           the script.




