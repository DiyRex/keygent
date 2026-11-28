# Contributing to keygent

Thanks for helping. keygent lets AI coding agents **use** secrets without **seeing** them, so a careless
change can leak the very values it exists to protect. These rules are deliberately strict. Read the whole page before
opening a pull request.

> keygent is pre-alpha. Interfaces, file formats and commands may still change. Large changes start as an issue, not
> a pull request.

## Ground rules

### Never use real secrets

Don't put real secrets in code, tests, fixtures, logs, screenshots, issues, commit messages or PR descriptions. Tests
use generated canaries of the form `KEYGENT_CANARY_<random>`.

If you think you leaked a real value, rotate it at the provider first, then tell the maintainer privately.

### Security rules for code

These are hard rules. A pull request that breaks one isn't merged.

- **Only the broker holds plaintext.** No broker request returns a secret value. Values reach a child process only as an
  environment variable or a private file binding, never through argv.
- **The plaintext boundary is enforced.**
  - Only `crypto/`, `vault/`, `broker/` and `redact/` (and `cli/` during authentication) may use the secret types
    (`Secret`, `Dek`, `Kek`, `Subkey`).
  - `policy/`, `proto/`, `hook/`, `adapter/` and `ui/` must not.
  - `scripts/preflight.sh` checks this, once the corresponding modules are on `main`.
- **Secret types** implement neither `Debug` nor `Display`, and they zeroize on drop. Never log, format or `clone()`
  a value into ordinary memory.
- **Never log values, commands or prompts.** The broker log takes fixed event names and numbers only. Audit records
  hold command *templates* (with placeholders), passed through the redactor.
- **No custom crypto.** Use only the RustCrypto crates already listed in `Cargo.toml`. Never write a primitive or
  construction yourself.
- **`unsafe` is denied crate-wide.** The only exception is `src/platform/`, where each block needs a
  `// SAFETY:` comment explaining why it is sound.
- **Fail closed.** If redaction, the audit log, the vault state or a pin check fails, refuse and return one
  `keygent:` error line. Never fall back to running without the protection.
- **Assume the agent is the same OS user.** Hooks, TTY checks and environment markers are UX, not security
  boundaries. Anything that matters is enforced in the broker.
- **Name the attacker tier** ([`docs/THREATS.md`](docs/THREATS.md)). Every security claim names its tier:
  - **T1:** a well-meaning agent making mistakes;
  - **T2:** a prompt-injected agent using generic exfiltration, including forged hook calls and file edits;
  - **T3:** an adaptive agent targeting keygent itself. Out of scope for v1; detected and documented.

### Engineering rules

| Area | Rule |
|---|---|
| Language | Stable Rust, edition 2024, MSRV 1.89 (`rust-version` in `Cargo.toml`). Don't use APIs newer than the MSRV |
| Concurrency | No async runtime. Use threads and blocking I/O |
| Size | The release binary must stay **≤ 3 MB** (target ≤ 2 MB). Check with `scripts/size-check.sh` |
| Dependencies | std first. A new crate needs a one-line justification in the PR (why std isn't enough) plus the binary size before and after |
| Lints | `cargo clippy --all-targets --all-features -- -D warnings` must be clean. No `unwrap`/`expect` outside tests, no unchecked indexing or arithmetic. Every `#[allow]` needs a `reason = "…"`; prefer `#[expect]` |
| Errors | User- and agent-facing errors are a single line starting with `keygent:`, at most 120 characters, naming the next action. Exit codes are stable (`77` policy deny, `78` sealed, `79` broker/internal, `64` usage, `74` run limit, `75` approval denied, `76` manifest not trusted) |
| Platforms | macOS, Linux and Windows. Platform-specific code lives in `src/platform/` behind the `Platform` trait. Say in the PR which platforms you tested |
| Tests | New behaviour gets a test. Security fixes get a regression test that fails without the fix. End-to-end tests run against the real binary with the `test-profile` feature and a temp `KEYGENT_TEST_ROOT`, never your real `~` |

Never run keygent's integration against your real `~/.claude` or other agent settings while developing. Point
`HOME` and `KEYGENT_TEST_ROOT` at a temp directory.

## Design documents

Read these before changing anything security-relevant:

| Document | What it covers |
|---|---|
| [`docs/SPEC.md`](docs/SPEC.md) | The full specification, and the source of truth |
| [`docs/THREATS.md`](docs/THREATS.md) | Assets, attacker tiers, controls, and known gaps |
| [`docs/adr/`](docs/adr/) | Architecture decisions. A change to the design needs a new ADR |
| [`docs/FORMATS.md`](docs/FORMATS.md) | Vault, index, manifest, audit and protocol formats |
| [`docs/ERRORS.md`](docs/ERRORS.md) | Every user- and agent-facing error line and exit code |
| [`docs/PLATFORMS.md`](docs/PLATFORMS.md) | Per-OS mechanisms |
| [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md) | Every crate, with its size and why std isn't enough |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phases and status |
| [`AGENTS.md`](AGENTS.md) | Rules for AI coding agents working in this repo |

If the spec is wrong or unsafe, say so in an issue and propose an ADR. Never deviate silently.

## Development setup

```sh
git clone https://github.com/DiyRex/keygent.git
cd keygent
rustup toolchain install   # installs the toolchain pinned in rust-toolchain.toml (stable + clippy + rustfmt)
cargo build
```

Optional: [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) for license and advisory checks.

## Before you open a pull request

No CI runs on pull requests (CI runs only when a maintainer starts it), so you run the gate locally and paste the result into the PR:

```sh
scripts/preflight.sh
```

It runs, in order:
1. `cargo fmt --check`;
2. clippy (all targets, `-D warnings`);
3. the test suite;
4. a release build and the 3 MB size check;
5. `cargo deny`, if installed.

As the broker lands on `main`, it also checks the plaintext boundary, where `unsafe` is used, runs the end-to-end tests
(`--features test-profile`), and checks that no test hooks are left in the release binary. Always run the version on
your branch.

If you touched platform code, also run the tests on every OS you can reach and list them in the PR.

## Releases (maintainers)

Releases use [GoReleaser](https://goreleaser.com) (`.goreleaser.yaml`) through `.github/workflows/release.yml`, which only runs by hand
([ADR 0017](docs/adr/0017-release-pipeline-and-updates.md)):

- **Snapshot** (any branch): Actions → release → Run workflow → `snapshot`. Binaries land on the run as artifacts; nothing is published.
  Locally: `goreleaser release --snapshot --clean --skip=sign` (needs `zig` and `cargo-zigbuild`).
- **Release**: bump `version` in `Cargo.toml` on `main`, tag `vX.Y.Z`, push the tag, then run the workflow from that tag with `release`.
  It publishes the signed release and updates `Formula/keygent.rb` in [DiyRex/homebrew-tap](https://github.com/DiyRex/homebrew-tap).

## Branches and commits

- **Branch from `main`**, named `<type>/<short-description>`. Types: `feat`, `fix`, `security`, `refactor`, `perf`,
  `docs`, `test`, `build`, `ci`, `chore`. Examples: `fix/redactor-hold-cap`, `docs/contributing`.
- **One concern per pull request.** Keep the diff as small as the change allows. Don't mix refactors with
  behaviour changes.
- **Commit messages use [gitmoji](https://gitmoji.dev):** one emoji, then an imperative summary of 50–72 characters,
  then a short bullet body of key points.

  ```text
  🐛 Fix redactor leaking a token after the hold cap

  - Keep swallowing token bytes after a capped detector match
  - Regression test streams 1 MiB of a token-shaped run
  ```

  Common choices: ✨ feature, 🐛 fix, 🔒️ security fix, ♻️ refactor, ⚡️ performance, ✅ tests, 📝 docs, 🔧 config,
  👷 CI, ➕/➖ dependencies, 💥 breaking change.
- Never put secrets, canaries or tokens in a commit message.

## Pull requests

1. **Open the PR against `main`.** Use a title in the same gitmoji format as a commit.
2. **Fill in every section of the template.** It appears automatically when you open the PR.
3. **Expect manual review.** The maintainer (@DiyRex) reviews every pull request by hand. Address comments with new
   commits; don't force-push over a review in progress.
4. **The maintainer merges.** Only the maintainer approves and merges, after the review is resolved and the checklist is
   complete. Contributors, including automated agents, never merge their own pull requests and never push to `main`.

A PR is ready for review when:
- the template is complete, including security impact and how you tested;
- `scripts/preflight.sh` passes, with the output summary in the PR;
- the binary size is reported if it changed;
- documentation and error messages are updated where behaviour changed.

## Reporting a vulnerability

**Don't open a public issue for security problems.** Use GitHub's private vulnerability reporting (*Security → Report
a vulnerability*). Include the attacker tier, the affected platforms, and a reproduction that uses canaries, never real
secrets.

## License

keygent is licensed under [Apache-2.0](LICENSE). By contributing, you agree your contribution is licensed under the
same terms (Apache-2.0 §5).
