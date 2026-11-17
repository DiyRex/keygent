# Platform matrix (SPEC v6)

How each primitive is implemented per OS. Diagram: [diagrams/07-platform-matrix.excalidraw](diagrams/07-platform-matrix.excalidraw).
Decisions: [ADR 0006](adr/0006-cross-platform.md). Every row is **verified in the Phase 0 spike** before use (SPEC §15 has the fallbacks).

## Locations (fixed, never derived from agent-steerable env vars at runtime)

| | Linux | macOS | Windows |
|---|---|---|---|
| Data (vault, index) | `~/.local/share/keygent/` from the passwd home dir (`getpwuid`, not `$HOME`); **XDG env vars are ignored at runtime** (an agent could steer them) | `~/Library/Application Support/keygent/` | `%LOCALAPPDATA%\keygent\` (known-folder API, not roaming) |
| Config (`config/global.toml`) | `~/.config/keygent/` (passwd home dir) | `~/Library/Application Support/keygent/config/` | `%APPDATA%\keygent\` (known-folder API) |
| State (audit) | `~/.local/state/keygent/` (passwd home dir) | `~/Library/Application Support/keygent/state/` | `%LOCALAPPDATA%\keygent\state\` |
| Broker endpoint | `/run/user/<uid>/keygent/broker.sock`, fallback `~/.local/state/keygent/run/` | `confstr(_CS_DARWIN_USER_TEMP_DIR)/keygent/broker.sock` | `\\.\pipe\keygent-<user SID>-<session id>` |
| Install (no admin) | `~/.local/bin` | `~/.local/bin` or Homebrew | `%LOCALAPPDATA%\Programs\keygent\` + user `PATH` |

## Primitives

| Concern | Linux | macOS | Windows |
|---|---|---|---|
| **IPC access** | 0700 dir owned by uid · `SO_PEERCRED` | 0700 dir · `getpeereid` | owner-SID-only DACL · `PIPE_REJECT_REMOTE_CLIENTS` · client token SID |
| **Exclusive bind** | `broker.lock` held for the broker's lifetime. If the socket exists, connect is refused and the lock is free → stale, so unlink and rebind. Otherwise refuse. If the path is > 100 B: bind via `/proc/self/fd/<dirfd>/broker.sock` (Linux); macOS uses a shorter per-user dir (`/tmp/keygent-<uid>/`, owner + 0700 verified) | same | `FILE_FLAG_FIRST_PIPE_INSTANCE` (a pipe disappears with its process, so no stale state) |
| **Broker scope** | one per OS user | one per OS user | one per user **and logon session** (RDP, fast user switching) |
| **Orphan control after broker crash** | `PR_SET_PDEATHSIG` on direct children + run-id sweep on next start | run-id sweep on next start | Job Object closes with the broker |
| **Suspend / clock** | dual monotonic + wall deadlines; seal on wake after a long suspend | same | same |
| **Broker identity** | mutual HMAC challenge-response (ADR 0004) | ← | ← |
| **Broker start** | spawn with cleared env, one inherited pipe, `setsid` | same | `CreateProcessW` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` (only the DEK pipe is inherited), `CREATE_NO_WINDOW` |
| **Secret memory** | locked arena + `mlockall` | locked arena (`mlock`) | locked arena (`VirtualLock` after `SetProcessWorkingSetSize`) |
| **Other heap** | zero-on-free allocator (locked by `mlockall`) | zero-on-free. Swap exposure documented | zero-on-free. Pagefile exposure documented |
| **No dumps / debug** | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` | `PT_DENY_ATTACH`, `RLIMIT_CORE=0`, hardened runtime when signed | WER exclusion (per-user), `SEM_NOGPFAULTERRORBOX`, process DACL with **OWNER RIGHTS** ACE (removes the owner's implicit WRITE_DAC) |
| **Injection** | static musl (no `LD_PRELOAD`) | hardened runtime + library validation (no `DYLD_*`) | `SetDefaultDllDirectories(SYSTEM32)`, static CRT, mitigation policies set at runtime on the broker only (not inherited by children) |
| **`NO_NEW_PRIVS`** | **not used** (it would be inherited and break `sudo`) | n/a | n/a |
| **Child containment** | process group + `PR_SET_CHILD_SUBREAPER`, kill the tree | process group + `KEYGENT_RUN_ID` env tag, `KERN_PROCARGS2` sweep at run end (**best effort**) | Job Object `KILL_ON_JOB_CLOSE`, no breakaway |
| **Interrupts** | SIGINT/SIGTERM → pgid | same | `CREATE_NEW_PROCESS_GROUP` + `CTRL_BREAK`, then `TerminateJobObject` |
| **Exec of pinned binary** | `fexecve` on the hash-verified fd | verify, then `posix_spawn` (TOCTOU documented) | verify, then `CreateProcessW` (TOCTOU documented) |
| **Shells (approved path)** | `/bin/sh` | `/bin/sh` | Git Bash `bash.exe`, `pwsh.exe` (absolute paths recorded at `integrate` with auth); `cmd.exe` unsupported |
| **Placeholder env ref** (non-argv positions only; argv use is refused by default, SPEC §3.2.6) | `"${KEYGENT_X}"` | same | bash `"${KEYGENT_X}"` · PowerShell `$env:KEYGENT_X` |
| **Minimal child env** | PATH (captured at unseal) HOME USER LOGNAME LANG LC_* TZ TMPDIR (+ `TERM=dumb NO_COLOR=1 PAGER=cat`) | same + `__CF_USER_TEXT_ENCODING` | PATH PATHEXT SystemRoot SystemDrive windir ComSpec TEMP TMP USERPROFILE APPDATA LOCALAPPDATA HOMEDRIVE HOMEPATH USERNAME ProgramData ProgramFiles* PROCESSOR_ARCHITECTURE NUMBER_OF_PROCESSORS |
| **File bindings** | `memfd_create` → `/dev/fd/N` | random 128-bit name in the owner-only run dir, deleted on exit | random name, owner-only DACL, `FILE_FLAG_DELETE_ON_CLOSE` + share-delete |
| **Secure files** | 0600/0700, `O_NOFOLLOW`, owner check | same | protected owner-only DACL, refuse reparse points |
| **Atomic replace** | temp + `fsync` + `rename` + `fsync(dir)` | temp + `F_FULLFSYNC` + `rename` | `ReplaceFileW` / `MoveFileExW(REPLACE_EXISTING\|WRITE_THROUGH)`, retry on sharing violations |
| **File lock** | `std::fs::File::lock` (MSRV 1.89) | ← | ← |
| **Passphrase input** | `/dev/tty`, termios echo off | same | `CONIN$`, console mode without echo |
| **Path canonicalization** | `realpath`, case-sensitive | `realpath`, case-insensitive | `GetFinalPathNameByHandleW`, case-insensitive, expand 8.3 names, strip `\\?\`, deny ADS |
| **Output encodings** | UTF-8 | UTF-8 | UTF-8 + UTF-16LE |
| **Native approval prompt** | none without root polkit policy → `keygent approve` / console | `LAContext.evaluatePolicy` (Touch ID / password) via `objc2`, broker reason text | **pending Phase 0 pass/fail** (needs per-request text: `UserConsentVerifier` or a per-grant Passport key); until then terminal + console only |
| **Reveal clipboard** (CLI) | `wl-copy` / X11 with `x-kde-passwordManagerHint=secret` | `NSPasteboard` + `org.nspasteboard.ConcealedType` | `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory=0`, `CanUploadToCloudClipboard=0` |
| **Rollback tripwire** | `secret-tool` (Secret Service) if running, else owner-only file `~/.local/state/keygent/` (also holds the device pepper) | Keychain item | Credential Manager |
| **Lock/sleep auto-seal** (Phase 6) | logind `Lock`, `PrepareForSleep` | `com.apple.screenIsLocked`, IOKit sleep | `WTS_SESSION_LOCK`, `PBT_APMSUSPEND` |
| **Same-user env read (known **T2** gap, SPEC §2.1)** | `/proc/<pid>/environ` | `KERN_PROCARGS2` | PEB via `ReadProcessMemory` |
| **Signing** | cosign + provenance | Developer ID + notarization + hardened runtime | Authenticode |
| **Hook p95** | 30 ms | 30 ms | 50 ms |

## Environments

| Environment | Support | Notes |
|---|---|---|
| macOS / Windows / Linux desktop | **Full** | Native approval prompt on macOS and Windows. Linux uses `keygent approve` or the console |
| WSL2 | Supported **as Linux** | Install the Linux build inside WSL. `/run/user/<uid>` may be missing (fallback dir). No native prompt. The console prints its URL for the Windows browser. A Windows-host Claude Code calling WSL keygent is unsupported |
| SSH / headless Linux | Supported | `unseal` needs a terminal. Approve from a second SSH session with `keygent approve`. No console auto-open |
| Windows RDP | Supported | Broker per logon session. Windows Hello may be unavailable over RDP, so fall back to `keygent approve` |
| Docker / devcontainers | Limited | One vault and broker per container. Mounting the host socket into containers is unsupported |
| CI / non-interactive | **Unsupported in v1** | No passphrase env var by design. `run` exits 78 |
| Network / sync folders for the vault | **Refused** | NFS, SMB, iCloud Drive, OneDrive, Dropbox (unreliable locking) |
| Managed Claude Code settings that disable user hooks | Detected | `doctor` reports that integration is ineffective |

## Spike checklist (Phase 0)

- [ ] Claude Code on Windows: Bash tool shell, PowerShell tool, hook execution and quoting
- [ ] LocalAuthentication and UserConsentVerifier from a windowless background process (fallback: helper process)
- [ ] `RLIMIT_MEMLOCK` defaults, `VirtualLock` working-set limits, macOS `mlock` limits for the secret arena — macOS ✓ unlimited, 256 MiB ok ([spike 04](spikes/04-platform-unix.md) §1); Linux desktop VM and Windows open
- [ ] OWNER RIGHTS ACE stops same-user `WRITE_DAC` on the broker process
- [ ] Which Windows mitigation policies break `std` or the CRT in the broker
- [ ] `PT_DENY_ATTACH` and hardened runtime with ad-hoc vs Developer ID signing — ad-hoc ✓: unentitled same-user attach refused even without it (spike 04 §3); `lldb` with Developer Mode open
- [ ] Defender and SmartScreen behavior for unsigned builds
- [x] `KERN_PROCARGS2` sweep reliability on macOS — **unreliable**: env stripped for Apple binaries on macOS 26 → [ADR 0009](adr/0009-macos-session-sweep.md) (proposed)
- [ ] WebAuthn on `http://localhost` (Safari, Chrome, Firefox, Edge)
- [ ] Confirm each env-read path (known T2 gap) so THREATS.md stays accurate — macOS ✓, Linux container ✓ (spike 04 §2); Windows PEB open
