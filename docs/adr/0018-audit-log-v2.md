# ADR 0018 — Audit log v2: who used which secret, with what, when; storage, retention, query

- **Status:** proposed
- **Date:** 2026-11-28
- **Verified against:**
  - keygent `feat/broker-and-run` (audit v1 as built, ADR 0015)
  - `miniz_oxide` 0.8 size and ratio, measured 2026-11-28 with the release profile (numbers below)
  - RustyVault 0.3.1 @ `4efe033` and HashiCorp Vault audit docs ([research note](../research/rustyvault-comparison.md))

## Context

keygent is the only path by which a secret reaches a process. Its audit log is therefore the one place where misuse can be
seen. The owner asked for:

- **Who:** which agent.
- **What:** which tool, and which secret.
- **When.**
- **How often**, so that something suspicious stands out.
- **Where to read it:** the CLI, with ranges and filters, and the web console.
- **How it is stored:** size, retention, compression, archive and backup.

Audit v1 (SPEC §9, FORMATS §5, ADR 0015) already gives a fail-closed HMAC chain. It has these gaps:

- It does not record the agent.
- The command template and cwd are stored **in clear**. An agent running as the same user can read the file (T2).
- Rotation is specified (10 MB × 5) but not built.
- There is no compression, retention policy, query language, statistics, alerting or export.
- AGENTS.md ("never log commands") and SPEC §9 (log the rendered template) contradict each other.

## Decision

### 1. What a record says, and how far it can be trusted

Every record separates **observed** fields, which the broker saw itself, from **reported** fields, which a client claimed.
The same OS user can forge anything reported. Reported fields help a human investigate, but they are **T1 only** and are
never used for policy.

| Field | Source | Meaning |
|---|---|---|
| `seq`, `ts` | observed | Monotonic sequence and wall clock (RFC 3339, UTC) |
| `event`, `decision`, `channel` | observed | As in v1 (`run`, `approve`, `deny`, `reveal`, …); the channel is `terminal`, `native`, `console` or `rule` |
| `handles` | observed | Handles injected (names only) |
| `set` | observed | Env set, if the run used one (ADR 0019) |
| `tool` | observed | `{path, sha256}` of the executable that received the secrets (the pinned program, or the first resolved program) |
| `peer` | observed | `{pid, exe}` of the connecting client (peer credentials). `exe` can be spoofed by the same user |
| `agent` | reported | Agent name from the hook adapter (`claude-code`, `codex`, …), or `cli` for a human at a terminal |
| `session`, `tool_use` | reported | The agent's session id and tool-use id from the hook payload, hashed with `K_audit` (linkable, not raw) |
| `x` | encrypted | Sealed confidential fields, see §2 |
| `exit`, `redactions`, `dur_ms`, `bytes_out` | observed | Run outcome |
| `grant_key` | observed | As in v1 |
| `mac` | | Chain MAC, always last |

`v` becomes `2`. Verifiers accept v1 lines that come before the first v2 line.

### 2. Confidential fields are encrypted, never stored in clear (RustyVault comparison, item 6)

- The command template, cwd and script paths go into `x`, sealed with XChaCha20-Poly1305:
  - key `K_audit_field = HKDF(DEK, "kg/v1/key/audit-field")`
  - AAD `enc("kg/v1/audit-x") ‖ enc(seq)`
  - `x` = hex(nonce ‖ ct)
- The chain MAC covers the ciphertext, so `audit --verify` needs no decryption.
- Showing commands (`--show-commands`, console "show command") needs fresh auth, the same as `reveal` metadata.
- Secret **values** are never in the log in any form. The template carries placeholders, and the redactor still runs over it before sealing.
- AGENTS.md changes to say: "Never log values or prompts. Commands are logged only encrypted (ADR 0018)."

### 3. Storage layout

```
state/audit/
  current.jsonl        active segment, append-only, owner-only (0600)
  seg-<first_seq>.jsonl.z   sealed segments, raw DEFLATE, read-only (0400)
  segments.idx         one MAC'd line per sealed segment
  audit.anchor         per-record anchors (as v1)
```

**`segments.idx`**
- Each line is `first_seq last_seq first_ts last_ts last_mac sha256(file) bytes_raw bytes_z hmac`.
- `hmac = HMAC(K_audit, enc(all prior fields))`.
- This lets `verify` and queries skip whole segments by time without decompressing them.

**Rotation**
- `current.jsonl` is sealed when it reaches **4 MiB** or is **30 days** old, whichever comes first.
- The chain continues across segments: the first record of the new segment chains from the last MAC of the old one.

**Compression: DEFLATE via `miniz_oxide`**
- Measured cost is **+33,312 bytes** of release binary.
- On a realistic 20,000-record sample, the data went from **7.38 MB to 2.03 MB (3.6×)**. Hex MACs and hashes don't compress, so the ratio is modest.
- std has no compressor, so the crate gets a DEPENDENCIES entry.
- Rejected alternative: no compression. That is still small (see the sizing below), so it is the fallback if the size budget gets tight.

**Durability**
- `run start` records are written with `write` + `fsync` before exec (fail closed, as v1).
- On macOS, `F_FULLFSYNC` is used only when a segment is sealed, to stay inside the 10 ms `run` overhead budget.
- If the disk is full or the file can't be written, runs are refused with exit 79, as v1.

**Sizing**
- A v2 record is about 400 B raw, about 110 B compressed. A run writes 2–3 records (grant/approve, start, end).
- Heavy use: 300 runs/day ≈ 900 records ≈ 360 KB/day raw, ≈ 100 KB/day compressed. That is **about 36 MB a year** before retention.
- `keygent audit stats --disk` prints the actual numbers.

### 4. Retention, archive, backup

**Retention**
- Defaults: keep **400 days** and at most **128 MiB** of compressed segments, whichever limit hits first.
- Both settings live in the **encrypted index** (SPEC §5.12).
- Lowering either limit, or retention below the **90-day floor**, is security-relaxing and needs auth.
- Pruning removes whole sealed segments, oldest first, and never removes the active one.

**`prune` record**
- Each prune appends `{"event":"prune","segments":[first..last],"checkpoint_seq":…,"checkpoint_mac":"…"}`.
- `verify` then starts from that MAC'd checkpoint, so a chain with a pruned head still verifies.
- Silent deletion by the same user is still detected through the anchors (§6).

**Archive ("reserve")**
- If `audit.archive_dir` is set (for example an external disk), pruned segments are **moved** there instead of deleted.
- `segments.idx` keeps their lines, marked `archived`.
- `keygent audit archive --to <dir> [--before <date>]` does the same thing on demand.

**Backup**
- `keygent audit export --since … --until … --out <file.kga>` writes a self-contained bundle: the segments, their index
  lines and the anchors, in a length-prefixed container (FORMATS §5.1, new).
- `keygent audit verify --archive <file.kga>` checks a bundle against the vault's `K_audit` (needs an unsealed broker).
- `keygent backup --with-audit` adds the audit directory next to the vault backup.

**Uninstall**
- The audit log is kept unless `--purge` is given (SPEC §12).

### 5. Reading it: CLI

```
keygent audit [--since <t>] [--until <t>] [--handle <h|prefix/*>] [--set <name>] [--agent <a>] [--tool <name|path>]
              [--event <e,…>] [--decision <d,…>] [--limit <n>] [--reverse] [--follow] [--json] [--show-commands]
keygent audit stats [--by handle|set|agent|tool|event|day|hour] [--since …] [--until …] [--alerts] [--disk] [--json]
keygent audit verify [--archive <file>]
keygent audit export --out <file> [--since …] [--until …] [--format kga|jsonl|ocsf]
keygent audit archive --to <dir> [--before <t>]
```

**Time arguments**
- `<t>` takes RFC 3339, a date (`2026-11-01`), or a relative time (`15m`, `24h`, `7d`).
- Ranges are closed-open.

**Output and access**
- The default output is a compact table: time, event, decision, handles or set, tool, agent, exit, redactions.
- `--json` prints one v2 record per line with `x` left out.
- `--show-commands` needs auth and decrypts `x` locally.
- Listing and stats read the segments directly and need no broker, since they show metadata only. `verify` and `--show-commands` need the broker or the passphrase.

**`stats`**
- `stats` answers "how many times was what used, by whom": counts plus first and last use, per group.
- Example: `keygent audit stats --by handle --since 7d`, or `--by agent,tool`.

### 6. Integrity limits (stated honestly)

- **T1/T2 tamper evidence.** The chain, the per-record anchor file, the index anchor on every vault write and the 10-min tripwire
  anchor together detect editing, reordering and truncation. They catch these unless the log, `audit.anchor`, the vault index and
  the keystore tripwire are all rolled back to one consistent older state.
- **Deletion.** A same-user attacker can delete the whole directory. The broker then refuses runs (it fails closed) until the
  human runs `keygent audit reset`, which needs auth and is itself the first record of a new chain. So deletion can't go unnoticed.
- **T3.** Off-box shipping (OCSF/syslog forwarding) is the only defence against a privileged attacker, and it is listed for Phase 6.

### 7. Suspicious-activity signals

`audit stats --alerts` reports the conditions below, and the console's Audit page highlights them. Each one is computed from
the log, so nothing is hidden state.

| Signal | Default threshold |
|---|---|
| Authentication failures | ≥ 5 in 10 min |
| Denied or policy-denied grants | ≥ 5 in 10 min, per agent session |
| Burst of use for one handle or set | > 30 runs in 10 min, or > 3× its 14-day hourly median |
| First use of a handle by a new tool (path or sha) or a new agent | any |
| A pinned program's hash changed (rule fallback to approve) | any |
| `capture`, `reveal`, `exposed`, `trust`, `rule add` | any (listed, not alarmed) |
| `verify` failure or `audit reset` | any (critical) |

From Phase 3, critical signals also raise a desktop notification.

### 8. Reading it: web console (ADR 0005, Phase 4)

The console gets an **Audit** page with:
- a timeline using the same filters as the CLI;
- per-handle and per-set usage counts with a 30-day sparkline;
- an agent × tool matrix;
- the alerts list;
- a chain-status badge (last `verify` result and time);
- export.

Showing a command needs a per-action passkey assertion, the same as other sensitive actions.

## Consequences

**Format and docs**
- FORMATS §5 gets v2, §5.1 the export container, and a segment-index line format.
- SPEC §9 is rewritten to match.
- AGENTS.md wording is fixed.
- DEPENDENCIES gets `miniz_oxide` (+33 KB).

**Who builds what**
- The hook adapter (Phase 3) must pass `agent`, `session` and `tool_use` in the grant request.
- Until then, `agent` is `cli` or `unknown`.

**Build order** (ROADMAP "Audit v2")
1. v2 records + encrypted `x`
2. query/stats CLI
3. rotation + compression + `segments.idx`
4. retention/prune/archive
5. export/verify bundle
6. alerts
7. console page

**Cost**
- Running the alert checks inside the broker on every write costs CPU, so they run lazily (on `stats`, the console, or every 10 min).
