"""Actual production frontend/backend PTY: a tall closure approval stays whole."""
import codecs
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import time
import pyte

config = json.loads(Path(sys.argv[1]).read_text())
root = Path(config['root'])
bin_dir = root / 'bin'
bin_dir.mkdir()
wrapper = bin_dir / 'nix'
wrapper.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
from pathlib import Path
root = Path(os.environ['PTY_FIXTURE_ROOT'])
if sys.argv[1] == 'run':
    (root / 'backend.pid').write_text(str(os.getpid()))
    os.write(2, b'BACKEND-LAUNCH-WARNING-MUST-NOT-REACH-TTY\\n')
    os.execv(os.environ['PTY_BACKEND'], [os.environ['PTY_BACKEND']] + sys.argv[4:])
with (root / 'evaluations').open('a') as log: log.write('evaluation\\n')
os.write(2, b'SCHEMA-RELOAD-WARNING-MUST-NOT-REACH-TTY\\n')
os.write(2, b'x' * 262144)
sys.stdout.write((root / 'schema.json').read_text())
''')
wrapper.chmod(0o700)
runtime = root / 'runtime'
runtime.mkdir(mode=0o700)
env = os.environ.copy()
env.update({'TERM':'xterm-256color', 'PATH':str(bin_dir) + ':' + env['PATH'], 'XDG_RUNTIME_DIR':str(runtime), 'PTY_FIXTURE_ROOT':str(root), 'PTY_BACKEND':config['backend']})
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 240, 180, 0, 0))
screen = pyte.Screen(180, 240)
stream = pyte.Stream(screen)
decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
raw = bytearray()
frontend = subprocess.Popen([config['frontend'], '--secret-identity', str(root/'identity'), '--', str(root)], stdin=slave, stdout=slave, stderr=slave, env=env, start_new_session=True)
os.close(slave)
requester = None

def display(): return '\n'.join(screen.display)
def pump():
    if select.select([master], [], [], .05)[0]:
        data = os.read(master, 65536)
        raw.extend(data)
        if b'\x1b[6n' in data: os.write(master, b'\x1b[1;1R')
        stream.feed(decoder.decode(data))
    if frontend.poll() is not None: raise RuntimeError('frontend exited: ' + display())
def wait(predicate, seconds=30):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        pump()
        if predicate(): return
    raise RuntimeError('PTY expectation timed out: ' + display())
try:
    wait(lambda: 'Ready' in display() and 'Actions' in display())
    # Startup progress printed before the TUI took over must not show
    # through blank cells, where it would corrupt dialog titles.
    assert screen.display[0].startswith('┌Filters · 1–7 select─'), display()
    requester = subprocess.Popen([config['frontend'], 'procedure', '--title', 'Update ns1', '--steps', '1', '--',
                                  config['frontend'], 'sign-closure', '--host', 'ns1', '--reason', config['reason'], config['identifier']],
                                 cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    requester.stdin.write(json.dumps(config['manifest']).encode())
    requester.stdin.close()
    requester.stdin = None
    def asked():
        if requester.poll() is not None:
            raise RuntimeError('requester exited: ' + requester.stderr.read().decode(errors='replace'))
        return 'Yes, send' in display() and 'denies in' in display()
    wait(asked, 60)
    # Let the countdown redraw a few times, as an operator would see it.
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline: pump()
    rendered = display()
    (root/'approval-screen.txt').write_text(rendered)
    proof = Path(os.environ.get('NIX_SECRETS_PTY_PROOF_DIRECTORY', '/tmp/nix-secrets-closure-approval-pty-proof'))
    proof.mkdir(parents=True, exist_ok=True)
    (proof/'approval-screen.txt').write_text(rendered)
    (proof/'terminal.raw').write_bytes(raw)
    assert '┌Update ns1 · step 1/1: sign closure for ns1─' in rendered, rendered
    assert 'Closure signing request from ' in rendered, rendered
    assert 'Requestor provides unvalidated reason:' in rendered, rendered
    for row, line in enumerate(screen.display):
        col = line.find('Yes, send')
        if col >= 0:
            x, y = col + 5, row + 1
            os.write(master, f'\x1b[<0;{x};{y}M\x1b[<0;{x};{y}m'.encode())
            break
    else: raise RuntimeError('approval button absent')
    wait(lambda: requester.poll() is not None)
    stdout, stderr = requester.communicate(timeout=5)
    assert requester.returncode == 0, stderr.decode(errors='replace')
    print('Actual production closure approval PTY proof: ' + str(proof))
finally:
    if requester is not None and requester.poll() is None: requester.kill(); requester.wait()
    if frontend.poll() is None: frontend.terminate(); frontend.wait(timeout=5)
    pidfile = root/'backend.pid'
    if pidfile.exists():
        pid = int(pidfile.read_text())
        try:
            cmdline = Path(f'/proc/{pid}/cmdline').read_bytes()
            if config['backend'].encode() in cmdline and str(root).encode() in cmdline: os.kill(pid, signal.SIGTERM)
        except FileNotFoundError: pass
    os.close(master)
