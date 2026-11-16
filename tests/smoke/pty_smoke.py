#!/usr/bin/env python3
"""Real-terminal smoke test (pty) for the console path the Rust tests can't reach: echo off, alternate screen,
keypress clear. Uses a test-profile build and an isolated KEYGENT_TEST_ROOT; never touches the real vault.
Usage: tests/smoke/pty_smoke.py <path-to-test-profile-keygent>"""
import os, pty, select, sys, tempfile, time

BIN = sys.argv[1]
PASS = b"orbit-canyon-velvet-anchor-mosaic-tundra"
CANARY = b"KEYGENT_CANARY_pTy7Qw9ZrX2mLk4VbN8sHd"


def spawn(args, root):
    pid, fd = pty.fork()
    if pid == 0:
        env = {"KEYGENT_TEST_ROOT": root, "KEYGENT_TEST_FAST_KDF": "1", "KEYGENT_TEST_USE_TTY": "1", "HOME": root, "TERM": "xterm"}
        os.execve(BIN, [BIN] + args, env)
    return pid, fd


def expect(fd, pat, buf, timeout=20):
    end = time.time() + timeout
    while pat not in buf[0]:
        if time.time() > end:
            raise SystemExit(f"FAIL: timeout waiting for {pat!r}; got {buf[0][-300:]!r}")
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                buf[0] += os.read(fd, 4096)
            except OSError:
                break
    i = buf[0].index(pat) + len(pat)
    before, buf[0] = buf[0][:i], buf[0][i:]
    return before


def shown(screen):
    """Secret line on the alternate screen: the first non-empty line after the header (pty may add \\r)."""
    body = screen.split(b"\x1b[2J")[-1]
    lines = [l.strip() for l in body.replace(b"\r", b"").split(b"\n") if l.strip()]
    return lines[1]


def finish(pid, fd, buf):
    while True:
        try:
            d = os.read(fd, 4096)
            if not d:
                break
            buf[0] += d
        except OSError:
            break
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)


root = tempfile.mkdtemp(prefix="kg-tty-")
seen = []

# init: own passphrase, recovery key on the alternate screen, cleared by a keypress
pid, fd = spawn(["init", "--own-passphrase"], root)
b = [b""]
expect(fd, b"New passphrase", b); os.write(fd, PASS + b"\r")
expect(fd, b"Repeat it:", b); os.write(fd, PASS + b"\r")
screen = expect(fd, b"(press any key to clear)", b)
assert b"\x1b[?1049h" in screen, "alternate screen not entered"
rk = shown(screen)
os.write(fd, b"x")  # keypress clears
expect(fd, b"\x1b[?1049l", b)
expect(fd, b"Type the recovery key back", b); os.write(fd, rk + b"\r")
code = finish(pid, fd, b)
seen.append(screen + b[0])
assert code == 0, f"init exit {code}: {b[0]!r}"

# add: the value typed with echo off must not come back from the terminal
pid, fd = spawn(["add", "smoke/key"], root)
b = [b""]
expect(fd, b"Passphrase:", b); os.write(fd, PASS + b"\r")
expect(fd, b"Value:", b); os.write(fd, CANARY + b"\r")
code = finish(pid, fd, b)
assert code == 0, f"add exit {code}: {b[0]!r}"
seen.append(b[0])

# reveal: shown on the alternate screen, cleared by a keypress well before the 20 s timeout
pid, fd = spawn(["reveal", "smoke/key"], root)
b = [b""]
expect(fd, b"Passphrase:", b); os.write(fd, PASS + b"\r")
t = time.time()
screen = expect(fd, b"(press any key to clear)", b)
assert shown(screen) == CANARY, "value not shown"
os.write(fd, b"q")
expect(fd, b"\x1b[?1049l", b)
assert time.time() - t < 5, "keypress did not clear the screen promptly"
code = finish(pid, fd, b)
assert code == 0, f"reveal exit {code}"

# echo-off: neither the passphrase nor the typed value was echoed in any session output
for out in seen:
    assert PASS not in out, "passphrase echoed"
    assert CANARY not in out, "value echoed while typing"
print("tty smoke: OK (echo off, alternate screen, keypress clear)")
