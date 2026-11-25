"""PID-1 payload deadline independent of host disk sampling and cleanup."""
import os,signal,subprocess,sys,time
from pathlib import Path

def remaining(pid_stat,uptime,hz):
    # /proc/PID/stat field22: process start ticks; comm can contain spaces/parentheses.
    ticks=int(pid_stat.rsplit(')',1)[1].split()[19])
    elapsed=uptime-ticks/hz
    if elapsed<0 or elapsed>180:raise ValueError('invalid/expired start time')
    return max(0,175-elapsed)  # five seconds retained for stop/exit within180

def main():
    if len(sys.argv)!=2 or sys.argv[1] not in ('worker','controller'):raise SystemExit(2)
    budget=remaining(Path('/proc/self/stat').read_text(),float(Path('/proc/uptime').read_text().split()[0]),os.sysconf('SC_CLK_TCK'))
    if budget<=0:raise SystemExit(124)
    p=subprocess.Popen(['/bin/sh','/control/'+sys.argv[1]+'.sh'],start_new_session=True)
    def stop(signum=None,frame=None):
        try:os.killpg(p.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    signal.signal(signal.SIGTERM,lambda a,b:(stop(),sys.exit(143)))
    try:
        code=p.wait(timeout=budget)
    except subprocess.TimeoutExpired:
        stop();code=124
    finally:
        stop()
        try:p.wait(timeout=2)
        except subprocess.TimeoutExpired:pass
    raise SystemExit(code)
if __name__=='__main__':main()
