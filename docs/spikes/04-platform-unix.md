# Spike 04 — platform primitives on macOS and Linux

- **Date:** 2026-11-16
- **Code:** throwaway spike crate (not published; `libc 0.2.191`). The raw output was captured on macOS arm64 and Linux (Docker, aarch64); the numbers below are taken from it.
- **macOS:** 26.6.2 arm64 (16 GB), SIP enabled, Developer Mode **disabled**, spike binary ad-hoc linker-signed (no hardened runtime).
- **Linux:** Docker Desktop LinuxKit kernel 7.0.12, `rust:1-bookworm` aarch64, probe run as `nobody`. **Not a desktop distro:**
  no Yama LSM, no systemd user session, Docker's memlock default. Desktop numbers still need a real VM (see "Still open").
- Canaries only (`KEYGENT_CANARY_<random>`).

## 1. Memory-lock limits (secret arena)

| | macOS 26.6.2 | Linux (container) |
|---|---|---|
| `RLIMIT_MEMLOCK` | soft/hard unlimited | soft/hard unlimited (Docker default; desktop systemd is usually 8 MiB) |
| Wire limit | `vm.user_wire_limit` = 13 056 700 579 (≈ 76 % of RAM) | n/a |
| `mlock` 64 KiB … 256 MiB | all ok | all ok |
| `mlockall(MCL_CURRENT\|MCL_FUTURE)` | n/a | ok |

**Conclusion:** the macOS arena is not limited in practice. The Linux desktop limit (8 MiB on systemd ≥ 253 / kernel ≥ 5.16) is still
unverified and decides whether `mlockall` fits the broker. The 8 MiB redactor pattern cap (SPEC row 169) plus the arena must stay under it, or
`doctor` must explain how to raise it.

## 2. Same-user env read (THREATS known gap #1)

| Target | macOS reader (`KERN_PROCARGS2`, `ps eww`) | Linux reader (`/proc/<pid>/environ`, `ps eww`) |
|---|---|---|
| plain process (ad-hoc / third-party binary) | **readable**, canary found | **readable**, canary found |
| process that called `PT_DENY_ATTACH` (macOS) / `PR_SET_DUMPABLE=0` (Linux) | **readable** (PT_DENY_ATTACH doesn't hide env) | **not readable** (EACCES), `ps` shows nothing |
| Apple platform binary (`/bin/sleep`, `/usr/bin/curl`) | **env stripped**: sysctl succeeds, argv returned, env absent | n/a |
| Homebrew `python3` (third-party) | readable, canary found | n/a |

**Conclusions:**
- The known T2 gap is confirmed on both OSes for third-party binaries, which covers most allow-rule tools (`stripe`, `node`, `python`).
- **New:** macOS 26 hides the env of Apple-signed platform binaries from same-user readers. That narrows the gap for e.g. `/usr/bin/curl`
  but must **not** be claimed as a control (version-dependent, undocumented). THREATS stays as is, with a note.
- Linux non-dumpable hides the broker's own env and memory. It resets on `execve`, so it never protects children (consistent with SPEC).

## 3. Same-user attach

| Target | macOS `ptrace(PT_ATTACHEXC)` | macOS `task_for_pid` | Linux `PTRACE_ATTACH` | Linux open `/proc/<pid>/mem` |
|---|---|---|---|---|
| plain | **refused** EPERM | refused (KERN_FAILURE) | **attached** (no Yama in the container) | **opened** |
| protected | refused EBUSY | refused | refused EPERM | refused EACCES |

**Conclusions:**
- macOS (SIP on, Developer Mode off): an unentitled same-user process can't attach to *any* process, even without PT_DENY_ATTACH. PT_DENY_ATTACH
  adds protection against entitled debuggers (`lldb`, which needs Developer Mode or an admin prompt). That attach path was **not exercised**
  (it raises an authorization dialog). Still open: verify with Developer Mode on.
- Linux: `PR_SET_DUMPABLE=0` is required and sufficient against same-user ptrace and `/proc/<pid>/mem`, even without Yama.

## 4. Orphan containment (double-fork survivors)

| Method | macOS | Linux |
|---|---|---|
| Env-tag sweep (`KEYGENT_RUN_ID` via `KERN_PROCARGS2` / `environ`), survivor keeps tag | **misses Apple binaries** (`sleep`, `sh`, `curl`: env stripped, see §2). Finds third-party (`python3`). Scan of ~1 350 pids: 12–21 ms | finds all |
| Env-tag sweep, survivor unsets the tag | missed (expected, documented escape) | missed |
| **Session-id sweep** (run started with `setsid()`, kill every pid with `getsid(pid) == run_sid`) | finds plain `&` and `nohup` survivors, incl. Apple binaries. Scan < 0.5 ms | same |
| Session-id sweep, survivor calls `setsid()` itself | missed (escape) | missed |
| `PR_SET_CHILD_SUBREAPER` + `killpg` | n/a | orphan reparented to the subreaper and reaped |

**Conclusion:** SPEC §5.4 / ADR 0006 / PLATFORMS describe the macOS sweep as "process group + `KEYGENT_RUN_ID` env-tag sweep". On macOS 26
that misses the most common survivors (shell builtins backgrounding `sleep`/`sh`/`curl`). **Proposal: ADR 0009** — start every run in its
own session and sweep by `getsid()` **and** the env tag (union). The remaining escape is a deliberate `setsid()` *and* a platform binary (or
unsetting the tag), which stays T3/best effort.

## 5. `PR_SET_PDEATHSIG` (Linux)

- A child with PDEATHSIG=SIGKILL dies when its parent process exits: **confirmed**.
- **Caveat confirmed:** PDEATHSIG fires when the **thread** that spawned the child exits, not the process. A child spawned from a short-lived
  thread is killed as soon as that thread ends. **Implementation rule for Phase 2:** the broker spawns every child from one long-lived spawner
  thread (or the main thread), never from per-connection threads.

## Still open (needs a machine or a human)

- Linux **desktop** VM: real `RLIMIT_MEMLOCK` default, Yama `ptrace_scope=1`, `/run/user/<uid>`, systemd user session.
- macOS: PT_DENY_ATTACH vs `lldb` with Developer Mode on; hardened runtime needs Developer ID signing (deferred by owner decision).
- macOS: `LAContext` from a windowless background process (needs a human for Touch ID). Probe ready to write.
- WebAuthn on `http://localhost` in Safari, Chrome, Firefox, Edge (needs a human with a passkey).
- All Windows items (PLATFORMS spike checklist).
