import os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from bounded import run
class BoundedTests(unittest.TestCase):
 def test_normal_output(self):
  code,out,err=run([sys.executable,'-c','print("ok")'])
  self.assertEqual((code,out,err),(0,b'ok\n',b''))
 def test_exited_leader_descendant_is_killed(self):
  with tempfile.TemporaryDirectory() as tmp:
   pidfile=Path(tmp)/'child.pid'
   child="import os,signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); open("+repr(str(pidfile))+",'w').write(str(os.getpid())); time.sleep(60)"
   parent="import subprocess,sys,time,os; subprocess.Popen([sys.executable,'-c',"+repr(child)+"]); p="+repr(str(pidfile))+";\nwhile not os.path.exists(p): time.sleep(.01)"
   pid=None
   try:
    with self.assertRaises(TimeoutError):run([sys.executable,'-c',parent],timeout=.5)
    pid=int(pidfile.read_text())
    # A dead orphan may briefly remain a zombie until init reaps it.
    deadline=time.monotonic()+2
    while time.monotonic()<deadline:
     try:os.kill(pid,0)
     except ProcessLookupError:break
     proc=Path('/proc')/str(pid)/'stat'
     try:
      if proc.read_text().rpartition(')')[2].split()[0]=='Z':break
     except FileNotFoundError:pass
     time.sleep(.05)
    else:self.fail('descendant survived process-group cleanup')
   finally:
    if pidfile.exists():
     try:os.kill(int(pidfile.read_text()),signal.SIGKILL)
     except ProcessLookupError:pass
