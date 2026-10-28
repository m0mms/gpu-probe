"""Bound child output while reading it; preserve failure evidence, never truncate."""
import os
import selectors
import signal
import subprocess
import time
import resource


def run(args, *, env=None, timeout=120, cap=4 * 1024 * 1024, file_cap=None):
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_cap, file_cap))
    p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, start_new_session=True,
                         preexec_fn=limits if file_cap is not None else None)
    streams = [bytearray(), bytearray()]
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as sel:
            for i, stream in enumerate((p.stdout, p.stderr)):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, i)
            while sel.get_map():
                if time.monotonic() >= deadline:
                    raise TimeoutError('command deadline')
                for key, _ in sel.select(.1):
                    raw = os.read(key.fd, 65536)
                    if not raw:
                        sel.unregister(key.fileobj)
                    else:
                        streams[key.data].extend(raw)
                        if sum(map(len, streams)) > cap:
                            raise ValueError('command output limit exceeded')
            return p.wait(timeout=max(.1, deadline-time.monotonic())), bytes(streams[0]), bytes(streams[1])
    finally:
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGTERM)
            try:
                p.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait(timeout=2)
        p.stdout.close()
        p.stderr.close()
