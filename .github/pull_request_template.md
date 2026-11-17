<!--
Title: gitmoji + imperative summary, e.g. "🐛 Fix redactor leaking a token after the hold cap".
Never paste real secrets, tokens or canaries anywhere in this pull request.
-->

## Summary

<!-- What changes and why, in 1–3 sentences. Link the issue: "Closes #123". -->

## Type of change

- [ ] ✨ Feature
- [ ] 🐛 Bug fix
- [ ] 🔒️ Security fix
- [ ] ♻️ Refactor (no behaviour change)
- [ ] ⚡️ Performance
- [ ] ✅ Tests only
- [ ] 📝 Documentation
- [ ] 👷 Build / CI / tooling
- [ ] 💥 Breaking change (format, CLI, exit code or protocol)

## Changes

<!-- Key points a reviewer needs; not a file list. -->

-

## Security impact

<!-- Required. Write "None" only if the change can't affect secrets, approvals, policy, redaction or audit. -->

- **Attacker tier affected** (T1 agent follows rules / T2 agent tries to bypass / T3 same-user code):
- **Plaintext boundary:** does any new code outside `crypto/`, `vault/`, `broker/`, `redact/` touch secret types? (yes / no)
- **Fail-closed behaviour:** what happens when this code fails?
- **New `unsafe`:** none / in `src/platform/` with `// SAFETY:` comments

## Dependencies and size

- **New or updated crates** (name, why std isn't enough):
- **Release binary size** (`scripts/size-check.sh`): before … bytes → after … bytes

## How I tested

<!-- Commands run and their result. Regression tests for fixes must fail without the fix. -->

- [ ] `scripts/preflight.sh` passes (paste the summary below)
- [ ] New or updated tests cover this change
- Platforms tested: [ ] macOS  [ ] Linux  [ ] Windows

```text
<preflight summary>
```

## Checklist

- [ ] Branch is from `main`, named `<type>/<short-description>`
- [ ] Commits use gitmoji titles with a short key-point body
- [ ] No real secrets anywhere; tests use `KEYGENT_CANARY_<random>`
- [ ] Agent-facing errors are one `keygent:` line ≤ 120 chars; exit codes unchanged or documented
- [ ] Every new `#[allow]` / `#[expect]` has a `reason`
- [ ] Docs and README updated where behaviour changed
- [ ] I understand the maintainer reviews and merges this PR; I won't merge it myself
