import locale
import os
import re
import signal
import subprocess
import sys
import time

DETACHED_PROCESS = 0x00000008
SLEEPTIME=1

def print_std(name, stdname, text):
  sys.stderr.write("%s for %s:\n" % (stdname, name))
  sys.stderr.write("----------\n")
  sys.stderr.write(text)
  if (not text.endswith("\n")): sys.stderr.write("\n")
  sys.stderr.write("----------\n")

def readfile(path):
  with open(path, "r") as file:
    return file.read()

class ProcessManager:
  def  __init__(self, sourcedir, tmpdir, tcpport, clientcount, cmdresult):
    self.cmdresult = cmdresult
    self.encoding = locale.getpreferredencoding()
    self.error = False
    self.processes = list()

    self.startserver(sourcedir, tmpdir, tcpport)
    if self.error: return
    for i in range(clientcount):
      time.sleep(SLEEPTIME)
      self.startclient(sourcedir, tmpdir, tcpport)
      if self.error: return

  def checkall(self):
    # check for and report any obvious errors in all processes
    for index in range(len(self.processes)):
      self.checkproc(index)

  def checkproc(self, index):
    # check for and report any obvious errors in the process
    name = self.getname(index)
    proc = self.processes[index]
    self.checkproc_stderr(proc, name)
    self.checkproc_returncode(proc, index, name)

  def checkproc_stderr(self, proc, name):
    # check for error output
    text = readfile(proc.stderrpath)

    if len(text) == 0: return
    self.cmdresult.report(False)
    sys.stderr.write("warning: output to stderr\n")
    print_std(name, "stderr", text)
    self.error = True

  def checkproc_returncode(self, proc, index, name):
    # check return code (note: server may legitimately be terminated)
    if proc.returncode == 0: return
    if index == 0 and proc.returncode == -signal.SIGTERM: return

    self.cmdresult.report(False)
    if proc.returncode == -signal.SIGTERM:
      sys.stderr.write("warning: %s terminated due to timeout\n" % (name))
    else:
      sys.stderr.write("warning: %s failed with exit code %d\n" % (name, proc.returncode))
    self.error = True

  def endinput(self, index):
    # close stdin for specified process
    proc = self.processes[index]
    if proc.stdin:
      proc.stdin.close()
      proc.stdin = None

  def endinputall(self):
    # close stdin for all processes
    for i in range(len(self.processes)):
      self.endinput(i)

  def getname(self, index):
    return "server" if index == 0 else "client%d" % (index)

  def matchline(self, lines, regexp, lineindexstart):
    for lineindex in range(lineindexstart, len(lines)):
      if re.fullmatch(regexp, lines[lineindex]):
        return lineindex
    return -1

  def matchoutput(self, index, regexps, unique):
    path = self.processes[index].stdoutpath
    text = readfile(path)
    lines = [line.rstrip() for line in text.split("\n")]
    lineindex = 0
    bad = False
    for regexp in regexps:
      lineindexmatch = self.matchline(lines, regexp, lineindex)
      if lineindexmatch >= 0:
        if (unique == True):
            lineindex = self.matchline(lines, regexp, lineindexmatch+1)
            if lineindex >= 0:
                 self.cmdresult.report(False)
                 sys.stderr.write("warning: expected output line not unique (regexp=\"%s\", path=\"%s\")\n" % (regexp, path))
                 self.error = True
                 bad = True
        lineindex = lineindexmatch + 1
      else:
        self.cmdresult.report(False)
        sys.stderr.write("warning: expected output line not found (regexp=\"%s\", path=\"%s\")\n" % (regexp, path))
        self.error = True
        bad = True
    if bad:
      print_std(self.getname(index), "stdout", text)

  def matchoutput_noorder(self, index, regexps, unique):
    path = self.processes[index].stdoutpath
    text = readfile(path)
    lines = [line.rstrip() for line in text.split("\n")]
    bad = False
    for regexp in regexps:
      lineindexmatch = self.matchline(lines, regexp, 0)
      if lineindexmatch >= 0:
        if (unique == True):
            lineindex = self.matchline(lines, regexp, lineindexmatch+1)
            if lineindex >= 0:
                 self.cmdresult.report(False)
                 sys.stderr.write("warning: expected output line not unique (regexp=\"%s\", path=\"%s\")\n" % (regexp, path))
                 self.error = True
                 bad = True
      else:
        self.cmdresult.report(False)
        sys.stderr.write("warning: expected output line not found (regexp=\"%s\", path=\"%s\")\n" % (regexp, path))
        self.error = True
        bad = True
    if bad:
      print_std(self.getname(index), "stdout", text)

  def nomatchoutput(self, index, regexps):
    path = self.processes[index].stdoutpath
    text = readfile(path)
    lines = [line.rstrip() for line in text.split("\n")]
    bad = False
    for regexp in regexps:
      lineindexmatch = self.matchline(lines, regexp, 0)
      if lineindexmatch != -1:
        self.cmdresult.report(False)
        sys.stderr.write("warning: expected line should not be found (regexp=\"%s\", path=\"%s\")\n" % (regexp, path))
        self.error = True
        bad = True
    if bad:
      print_std(self.getname(index), "stdout", text)

  def sendinput(self, index, text):
    # send text to stdin of process
    stdin = self.processes[index].stdin
    #stdin.write(text.encode(self.encoding)) # Write without encoding
    stdin.write(text)
    stdin.flush()
    time.sleep(SLEEPTIME)

  def startprogram(self, sourcedir, tmpdir, args):
    # files to redirect output to
    index = len(self.processes)
    stdoutpath = os.path.join(tmpdir, "stdout%d.txt" % (index))
    stderrpath = os.path.join(tmpdir, "stderr%d.txt" % (index))
    if not os.path.isdir(tmpdir): os.makedirs(tmpdir)

    try:
      # start process
      with open(stdoutpath, "w") as stdout:
        with open(stderrpath, "w") as stderr:
          proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, close_fds=True, cwd=sourcedir, universal_newlines=True) # Added universal_newlines
    except OSError as e:
      # report failure
      self.cmdresult.report(False)
      sys.stderr.write("error: failed to start %s: %s\n" % (" ".join(args), e.strerror))
      self.error = True
    else:
      # store process info
      proc.stdoutpath = stdoutpath
      proc.stderrpath = stderrpath
      self.processes.append(proc)

  def startserver(self, sourcedir, tmpdir, tcpport):
    args = ["./server", str(tcpport)]
    self.startprogram(sourcedir, tmpdir, args)

  def startclient(self, sourcedir, tmpdir, tcpport):
    args = ["./client", "localhost", str(tcpport)]
    self.startprogram(sourcedir, tmpdir, args)

  def waitall(self):
    # closing stdin should terminate well-written clients
    self.endinputall()
    time.sleep(SLEEPTIME)

    # if there are still clients running, they are probably unresponsive and
    # must be terminated explicitly; the server always needs explicit
    # termination
    running = False
    for proc in self.processes:
      if proc.returncode == None: proc.poll()
      if proc.returncode == None: running = True

    if running: time.sleep(SLEEPTIME)

    for proc in reversed(self.processes):
      if proc.returncode == None: proc.poll()
      if proc.returncode == None:
        proc.terminate()
        proc.wait()

    # any errors to report?
    self.checkall()
