"""Actual production frontend/backend PTY regression; no operator substitute."""
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
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 48, 180, 0, 0))
screen = pyte.Screen(180, 48)
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
    sockets = list((runtime/'nix-secrets').glob('backend*.sock'))
    assert len(sockets) == 1, sockets
    requester = subprocess.Popen([config['frontend'], 'sign-artifacts', '--backend-socket', str(sockets[0]), '--host', 'host', '--reason', config['reason'], config['identifier']], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    requester.stdin.write(json.dumps(config['manifest']).encode())
    requester.stdin.close()
    requester.stdin = None
    wait(lambda: config['reason'] in display() and config['identifier'] in display() and 'Yes, send' in display())
    rendered = display()
    assert 'Artifact signing request' in rendered, rendered
    heading = next(line for line in screen.display if '┌Artifact signing request' in line)
    left = heading.index('┌Artifact signing request')
    right = heading.index('┐', left)
    modal_text = ' '.join(' '.join(line[left + 1:right].split()) for line in screen.display)
    assert 'Only detached signatures are returned.' in modal_text, rendered
    assert 'Requestor provides unvalidated reason:' in rendered, rendered
    assert b'SCHEMA-RELOAD-WARNING-MUST-NOT-REACH-TTY' not in raw, 'schema warning leaked into actual PTY'
    assert b'BACKEND-LAUNCH-WARNING-MUST-NOT-REACH-TTY' not in raw, 'launcher warning leaked into actual PTY'
    assert len((root/'evaluations').read_text().splitlines()) >= 3, 'request reload not exercised'
    (root/'approval-screen.txt').write_text(rendered)
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
    (root/'signatures.json').write_bytes(stdout)
    assert b'SCHEMA-RELOAD-WARNING-MUST-NOT-REACH-TTY' not in raw
    (root/'terminal.raw').write_bytes(raw)
    proof = Path(os.environ.get('NIX_SECRETS_PTY_PROOF_DIRECTORY', '/tmp/nix-secrets-artifact-approval-pty-proof'))
    proof.mkdir(parents=True, exist_ok=True)
    (proof/'approval-screen.txt').write_text(rendered)
    (proof/'terminal.raw').write_bytes(raw)
    (proof/'signatures.json').write_bytes(stdout)
    print('Actual production approval PTY proof: ' + str(proof))
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
