#!/usr/bin/env python3
"""Broker idle RSS (SPEC §4: unsealed broker idle RSS ≤ 5 MB). Uses a release build with the test-profile feature and an
isolated KEYGENT_TEST_ROOT, with N canary secrets. Usage: tests/smoke/broker_rss.py <keygent> [secrets]"""
import os, subprocess, sys, tempfile, time, secrets as rnd

BIN = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 20
PASS = "orbit-canyon-velvet-anchor-mosaic-tundra"
root = tempfile.mkdtemp(prefix="kg-rss-")
env = {"KEYGENT_TEST_ROOT": root, "KEYGENT_TEST_FAST_KDF": "1", "HOME": root, "PATH": "/usr/bin:/bin"}


def run(args, lines):
    return subprocess.run([BIN] + args, input="".join(l + "\n" for l in lines), env=env, capture_output=True, text=True, timeout=60)


p = subprocess.Popen([BIN, "init", "--own-passphrase"], stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
p.stdin.write((PASS + "\n" + PASS + "\n").encode()); p.stdin.flush()
buf = b""
while b"(press any key" not in buf:
    buf += p.stderr.read(1)
rk = buf.split(b"\x1b[2J")[-1].replace(b"\r", b"").split(b"\n")
rk = [l.strip() for l in rk if l.strip()][1]
p.stdin.write(rk + b"\n"); p.stdin.close(); assert p.wait() == 0, "init failed"
for i in range(N):
    r = run(["add", f"svc/k{i}"], [PASS, "KEYGENT_CANARY_" + rnd.token_urlsafe(24)])
    assert r.returncode == 0, r.stderr
r = run(["unseal"], [PASS]); assert r.returncode == 0, r.stderr
time.sleep(1.0)
pid = open(os.path.join(root, "run/broker.lock")).read().split()[1]
rss_kib = int(subprocess.run(["ps", "-o", "rss=", "-p", pid], capture_output=True, text=True).stdout.strip())
run(["seal"], [])
mb = rss_kib / 1024
print(f"broker idle RSS: {rss_kib} KiB ({mb:.2f} MiB) with {N} secrets — budget 5 MB: {'OK' if mb <= 5 else 'OVER'}")
sys.exit(0 if mb <= 5 else 1)
