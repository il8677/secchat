#!/usr/bin/env python3 

import locale
import os
import random
import shutil
import subprocess
import sys
import time

import procman

# exit code:
# - 0: no errors or warnings
# - 1: warning(s) that should be fixed
# - 2: error that should be fixed and caused tests to be aborted

warnings=False
tcpport_last=0
testindex=0
TCP_PORT_MIN=5000
TCP_PORT_MAX=32767

# Controls all tests (Less relevant for Deadline 1A)
advanced=False

chat_messages = { "register_success" : "registration succeeded", 
                  "register_failed" : "error: user {} already exists", 
                  "login_success" : "authentication succeeded",
                  "login_failed" : "error: invalid credentials",
                  "bad_format" : "error: invalid command format",
                  "privmsg_failed" : "error: user not found",
                  "unknown_command" : "error: unknown command {}",
                  "unavailable_command" : "error: command not currently available"
                  }

class CommandResult:
  def __init__(self):
    self.is_done = False

  def report(self, success):
    if self.is_done: return
    sys.stdout.write(" %s\n" % ("success" if success else "failed"))
    self.is_done = True

def die(msg):
  sys.stderr.write("%s\n" % msg)
  sys.exit(2)

def get_tcpport():
  global tcpport_last
  # avoid reusing ports in case an earlier server has not released the port yet
  if tcpport_last:
    tcpport_last += 1
    if tcpport_last > TCP_PORT_MAX:
      tcpport_last = tcpport_last - TCP_PORT_MAX + TCP_PORT_MIN
  else:
    tcpport_last = random.randint(TCP_PORT_MIN, TCP_PORT_MAX)
  return tcpport_last

def list_files_mtimes(dir):
  fileset = set()
  for root, dirs, files in os.walk(dir):
    for file in files:
      path = os.path.join(root, file)
      fileset.add((path, os.path.getmtime(path)))
  return fileset

def run_make(dir, target):
  global warnings

  sys.stdout.write("running make %s..." % (target))
  cmdresult = CommandResult()
  try:
    result = subprocess.run(["make", target], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd=dir)
  except OSError as e:
    cmdresult.report(False)
    sys.stderr.write("error: failed to start make: %s\n" % (e.strerror))
    sys.exit(2)

  if result.returncode != 0:
    cmdresult.report(False)
    if result.returncode < 0:
      sys.stderr.write("error: make failed with signal %d\n" % (-result.returncode))
    else:
      sys.stderr.write("error: make failed with exit code %d\n" % (result.returncode))

    stderrtext = result.stderr.decode(locale.getpreferredencoding())
    procman.print_std("make", "stderr", stderrtext)
    sys.exit(2)

  if result.stderr:
    cmdresult.report(False)
    sys.stderr.write("warning: make gave warning(s)\n")
    stderrtext = result.stderr.decode(locale.getpreferredencoding())
    procman.print_std("make", "stderr", stderrtext)
    warnings = True
    return

  cmdresult.report(True)

# Execute server and two clients 
def callback_check_start_one(pm):
  # executed with one client
  pass

def callback_check_start_two(pm):
  # executed with two clients
  pass

# Callbacks for /register command verification
def callback_check_register(pm):
  # executed with one client
  pm.sendinput(1, "/register erik hunter2\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["register_success"]], True)

def callback_check_register_failed(pm):
  # executed with one client
  pm.sendinput(1, "/register erik dummypass\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["register_failed"].format("erik")], True)

# Callbacks for /login command verification
def callback_check_login(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["login_success"]], True)

def callback_check_login_failed_cred_badpass(pm):
  # executed with one client
  pm.sendinput(1, "/login erik badpass\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["login_failed"]], True)

def callback_check_login_failed_cred_baduser(pm):
  # executed with one client
  pm.sendinput(1, "/login baduser hunter2\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["login_failed"]], True)

# Callback generators for command formatting errors
def get_check_badargs_function(pm, cmd, args):
  #sys.stdout.write("Command is :"+cmd + " " + " ".join(arg for arg in args)+"\n")
  pm.sendinput(1, cmd + " " + " ".join(arg for arg in args)+"\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["bad_format"]], True)

def get_check_badargs_function_logged(pm, cmd, args):
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, cmd + " " + " ".join(arg for arg in args)+"\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["bad_format"]], True)

def gen_callback_check_bad_formatting(cmd, args):
  return lambda pm : get_check_badargs_function(pm, cmd, args)

def gen_callback_check_bad_formatting_logged(cmd, args):
   return lambda pm : get_check_badargs_function_logged(pm, cmd, args)

# Callback generators for invalid commands
def get_check_invalidcmd_function(pm, cmd, args):
  pm.sendinput(1, cmd + " " + " ".join(arg for arg in args)+"\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["unknown_command"].format(cmd)], True)

def gen_callback_check_invalid_command(cmd, args):
  return lambda pm: get_check_invalidcmd_function(pm, cmd, args)

# Callback generators for unavailable commands
def get_unlogged_unavailablecmd_function(pm, cmd, args):
  pm.sendinput(1, cmd + " " + " ".join(arg for arg in args)+"\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["unavailable_command"]], True)  

def get_logged_unavailablecmd_function(pm, cmd, args):
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, cmd + " " + " ".join(arg for arg in args)+"\n")
  pm.waitall()
  pm.matchoutput(1, [chat_messages["unavailable_command"]], True) 

def gen_callback_check_unlogged_unavailable_commands(cmd, args):
  return lambda pm: get_unlogged_unavailablecmd_function(pm, cmd, args)

def gen_callback_check_logged_unavailable_commands(cmd, args):
  return lambda pm: get_logged_unavailablecmd_function(pm, cmd, args)

REGEXP_TIMESTAMP = "20[0-9][0-9]-[01][0-9]-[0-3][0-9] [0-2][0-9]:[0-5][0-9]:[0-6][0-9]"
REGEXP_PUBMSG1 = REGEXP_TIMESTAMP + " erik: pubmsg1"
REGEXP_PUBMSG2 = REGEXP_TIMESTAMP + " erik: pubmsg2"

def callback_check_pubmsg_send(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, "pubmsg1\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_PUBMSG1], True)

def callback_check_pubmsg_retr(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_PUBMSG1], True)

def callback_check_pubmsg_recv(pm):
  # executed with one client
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(2, "/register user2 iloveyou\n")
  pm.sendinput(1, "pubmsg2\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_PUBMSG1, REGEXP_PUBMSG2], True)
  pm.matchoutput(2, [REGEXP_PUBMSG1, REGEXP_PUBMSG2], True)

def callback_check_privmsg_send(pm):
  # executed with two clients
  pm.sendinput(2, "/register sam hereforfun\n")
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, "@user2 this is privmsg1\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1"], True)

def callback_check_privmsg_retr(pm):
  global advanced
  # executed with three clients
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(2, "/login user2 iloveyou\n")
  pm.sendinput(3, "/login sam hereforfun\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1"], True)
  pm.matchoutput(2, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1"], True)
  if advanced == True:
     pm.nomatchoutput(3, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1"])

def callback_check_privmsg_recv(pm):
  global advanced
  # executed with three clients
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(2, "/login user2 iloveyou\n")
  pm.sendinput(3, "/login sam hereforfun\n")
  pm.sendinput(2, "@erik this is privmsg2\n")
  pm.waitall()
  pm.matchoutput(1, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1", REGEXP_TIMESTAMP+" user2: @erik this is privmsg2" ], True)
  pm.matchoutput(2, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1", REGEXP_TIMESTAMP+" user2: @erik this is privmsg2" ], True)
  if advanced == True:
     pm.nomatchoutput(3, [REGEXP_TIMESTAMP+" erik: @user2 this is privmsg1", REGEXP_TIMESTAMP+" user2: @erik this is privmsg2" ])

def callback_check_privmsg_failed(pm):
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, "@notregistered msg not sent\n")
  pm.waitall()
  pm.nomatchoutput(1, [REGEXP_TIMESTAMP+" erik: @notregistered msg not sent"])
  pm.matchoutput(1, [chat_messages["privmsg_failed"]], True)

def callback_check_users_one(pm):
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(1, "/users\n")
  pm.waitall()
  pm.matchoutput(1, ["erik"], True)
  pm.nomatchoutput(1, ["sam" , "user2"])

def callback_check_users_two(pm):
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(2, "/register manuel alsofun\n")
  pm.sendinput(1, "/users\n")
  pm.waitall()
  pm.matchoutput_noorder(1, ["erik", "manuel"], True)
  pm.nomatchoutput(1, ["user2"])

def callback_check_users_three(pm):
  pm.sendinput(1, "/login erik hunter2\n")
  pm.sendinput(2, "/login manuel alsofun\n")
  pm.sendinput(3, "/login user2 iloveyou\n")
  pm.sendinput(1, "/users\n")
  pm.waitall()
  pm.matchoutput_noorder(1, ["erik", "manuel", "user2"], True)
  pm.nomatchoutput(1, ["sam"])

def callback_check_whitespaces(pm):
  pm.sendinput(1, "/login     erik    hunter2    \n")
  pm.sendinput(1, "   This       is   a public message      \n")
  pm.sendinput(1, "   @sam    How are you     \n")
  pm.waitall()
  pm.matchoutput(1, [ chat_messages["login_success"], REGEXP_TIMESTAMP+" erik: This       is   a public message" ,  REGEXP_TIMESTAMP + " erik: @sam How are you" ], True)

def interact(sourcedir, tmpdir, clientcount, callback, msg):
  global testindex, warnings

  # show progress
  sys.stdout.write(msg)
  cmdresult = CommandResult()

  # each test gets their own tempdir for output
  testindex += 1
  tmpdirtest = os.path.join(tmpdir, "test%d" % (testindex))

  # create all processes
  pm = procman.ProcessManager(sourcedir, tmpdirtest, get_tcpport(), clientcount, cmdresult)
  try:
    # interact with processes to perform test
    callback(pm)
  finally:
    # clean up and return status
    pm.waitall()
    warnings = warnings or pm.error
    cmdresult.report(True)

def check_build(dir):
  sys.stdout.write("executables built? ...")
  cmdresult = CommandResult()

  serverpath = os.path.join(dir, "server")
  if not os.path.isfile(serverpath):
    cmdresult.report(False)
    die("file %s does not exist" % (serverpath))

  clientpath = os.path.join(dir, "client")
  if not os.path.isfile(clientpath):
    cmdresult.report(False)
    die("file %s does not exist" % (clientpath))

  cmdresult.report(True)

def check_clean(dir):
  global warnings

  sys.stdout.write("source directory clean? ...")
  cmdresult = CommandResult()

  # verify that the directory contains no files that must be deleted by make clean
  for name in os.listdir(dir):
    if name in ["server", "client", "chat.db"] or name.endswith(".o"):
      cmdresult.report(False)
      sys.stderr.write("warning: file %s remains after clean\n" % (os.path.join(dir, name)))
      warnings = True

  cmdresult.report(True)

def check_filediff(dir, filesdiff, isnew):
  global warnings
  # verify that only files have been modified that the assignment allows
  pathchatdb = os.path.join(dir, "chat.db")
  pathclientkeys = os.path.join(dir, "clientkeys")
  pathserverkeys = os.path.join(dir, "serverkeys")
  pathtesttmp = os.path.join(dir, "test-tmp")
  for path, mtime in sorted(filesdiff):
    if path == pathchatdb: continue
    if path.startswith(pathclientkeys): continue
    if path.startswith(pathserverkeys): continue
    if path.startswith(pathtesttmp): continue
    
    sys.stderr.write("warning: file %s has been %s or modified by the program\n" % (path, "created" if isnew else "deleted"))
    warnings = True

def check_files(dir, filesbefore, filesafter):
  check_filediff(dir, filesbefore - filesafter, False)
  check_filediff(dir, filesafter - filesbefore, True)

print("""secchat test framework
----------------------

This program tests some of the basic functionality required in the SecChat
assignment for the Secure Programming course. If any of the tests fail,
you have not correctly implemented these requirements, and the chance of getting
a sufficient grade is rather low. If you DO pass the test, it is no guarantee
that you will also pass the assignment because many requirements cannot be
tested automatically.

usage:
  test.py path-to-source

The path-to-source parameter specifies the directory where your Makefile is
stored, and where your programs client and server are created after compilation.
Other files may be stored in subdirectories of this directory. Make sure your
programs work no matter where path-to-source is located, so avoid absolute paths
in your code or Makefile.


test progress
-------------
""")

# parameter sanity test
if len(sys.argv) < 2: die("path-to-source not specified")
if len(sys.argv) > 3: die("unexpected parameter(s)")

if len(sys.argv) == 3:
   if sys.argv[2] == "advanced":
         advanced = True
   else:
         die("unexpected second param")
        

sourcedir = sys.argv[1]
if not os.path.isdir(sourcedir): die("directory %s does not exist" % (sourcedir))

makefile = os.path.join(sourcedir, "Makefile")
if not os.path.isfile(makefile): die("file %s does not exist" % (makefile))

# make clean, and verify cleanness (avoids stale files)
run_make(sourcedir, "clean")
check_clean(sourcedir)

# build the code
run_make(sourcedir, "all")
check_build(sourcedir)

# clear temp dir
tmpdir = os.path.join(sourcedir, "test-tmp")
if os.path.isdir(tmpdir): shutil.rmtree(tmpdir)

# remember which files exist
filesbefore = list_files_mtimes(sourcedir)

# run the actual experiments
# Test if clients start without errors.
interact(sourcedir, tmpdir, 1, callback_check_start_one,   "running with single client...")
interact(sourcedir, tmpdir, 2, callback_check_start_two,   "running with two clients...")
interact(sourcedir, tmpdir, 3, callback_check_start_one,   "running with three clients...")

# registration tests
interact(sourcedir, tmpdir, 1, callback_check_register,    "testing /register (correct registration)...")
if advanced == True:
  interact(sourcedir, tmpdir, 1, callback_check_register_failed,    "testing /register (user already registered)...")

# formatting errors
sys.stdout.write("Starting /register formatting tests...\n")
time.sleep(0.5)
interact(sourcedir, tmpdir, 1, 
         gen_callback_check_bad_formatting("/register", []) ,    
        "testing /register format error (zero arguments)...")

interact(sourcedir, tmpdir, 1, 
         gen_callback_check_bad_formatting("/register", ["justin"]) ,    
         "testing /register format error (one argument)...")

interact(sourcedir, tmpdir, 1, 
          gen_callback_check_bad_formatting("/register", ["justin", "pass", "spuriousarg"]) ,     
         "testing /register format error (too many arguments)...")

# /login tests
interact(sourcedir, tmpdir, 1, callback_check_login,       "testing /login (correct login)...")

if advanced == True:
 interact(sourcedir, tmpdir, 1, callback_check_login_failed_cred_badpass,       "testing /login (bad password)...")
 interact(sourcedir, tmpdir, 1, callback_check_login_failed_cred_baduser,       "testing /login (unregistered user)...")

# /login formatting errors
sys.stdout.write("Starting /login formatting tests...\n")
time.sleep(0.5)
interact(sourcedir, tmpdir, 1, 
         gen_callback_check_bad_formatting("/login", []) ,    
        "testing /login format error (zero arguments)...")

interact(sourcedir, tmpdir, 1, 
         gen_callback_check_bad_formatting("/login", ["justin"]) ,    
         "testing /login format error (one argument)...")

interact(sourcedir, tmpdir, 1, 
          gen_callback_check_bad_formatting("/login", ["justin", "pass", "spuriousarg"]) ,     
         "testing /login format error (too many arguments)...")

# simple public message tests
interact(sourcedir, tmpdir, 1, callback_check_pubmsg_send, "testing simple public message send...")
interact(sourcedir, tmpdir, 1, callback_check_pubmsg_retr, "testing simple public message retrieve...")
interact(sourcedir, tmpdir, 2, callback_check_pubmsg_recv, "testing simple public message receive...")

# simple private message tests
interact(sourcedir, tmpdir, 2, callback_check_privmsg_send, "testing simple private message send...")
interact(sourcedir, tmpdir, 3, callback_check_privmsg_retr, "testing simple private message retrieve...")
interact(sourcedir, tmpdir, 3, callback_check_privmsg_recv, "testing simple private message receive...")

if advanced == True:
  interact(sourcedir, tmpdir, 1, callback_check_privmsg_failed, "testing simple private message send (unregistered user)...")

# /users tests 
if advanced == True:
   interact(sourcedir, tmpdir, 1, callback_check_users_one, "testing /users command (1 user logged)...")
   interact(sourcedir, tmpdir, 2, callback_check_users_two, "testing /users command (2 users logged)...")
   interact(sourcedir, tmpdir, 3, callback_check_users_three, "testing /users command (3 users logged)...")

# /users formatting error
interact(sourcedir, tmpdir, 1, 
          gen_callback_check_bad_formatting_logged("/users", ["spuriousarg"]) ,     
         "testing /users format error (too many arguments)...")

# invalid commands tests
sys.stdout.write("Testing for invalid commands...\n")
time.sleep(0.5)
interact(sourcedir, tmpdir, 1, gen_callback_check_invalid_command("/make", []), "testing unknown command /make...")
interact(sourcedir, tmpdir, 1, gen_callback_check_invalid_command("/loginer", ["erik", "hunter2"]), "testing unknown command /loginer...")

# unavailable commands tests
sys.stdout.write("Testing for unavailable commands...\n")
time.sleep(0.5)
interact(sourcedir, tmpdir, 1, gen_callback_check_unlogged_unavailable_commands("", ["howdy y'all"]), "testing send public message (not logged) ...")
if advanced == True:
  interact(sourcedir, tmpdir, 1, gen_callback_check_unlogged_unavailable_commands("/users", []), "testing /users command (not logged)...")
  interact(sourcedir, tmpdir, 1, gen_callback_check_unlogged_unavailable_commands("", ["@erik can we ask a question"]), "testing private message (not logged)...")

interact(sourcedir, tmpdir, 1, gen_callback_check_logged_unavailable_commands("/register", ["justin", "strongpass"]), "testing /register command (logged) ...")
interact(sourcedir, tmpdir, 1, gen_callback_check_logged_unavailable_commands("/login", ["justin", "strongpass"]), "testing /login command (logged) ...")

# whitespace tests
interact(sourcedir, tmpdir, 1, callback_check_whitespaces, "testing if whitespaces are handled correctly ...")

# TODO upcomming hardcore send private/public messages

# check whether any files were modified that should not have been
filesafter = list_files_mtimes(sourcedir)
check_files(sourcedir, filesbefore, filesafter)

# done!
if warnings: sys.exit(1)
