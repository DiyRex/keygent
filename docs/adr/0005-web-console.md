# ADR 0005 — Local web console with passkeys

- **Status:** accepted (revised through SPEC v6). Built in **Phase 4**.
- **Date:** 2026-11-15
- **Verified against:** design only. The spike must confirm WebAuthn on `http://localhost` in Safari, Chrome, Firefox and Edge (fallback in SPEC §15).

## Context

The owner wants a passkey-protected web UI to see and manage secrets. A same-user agent can send HTTP to localhost, act as a
software WebAuthn client, kill processes and bind ports. WebAuthn prompts show only "localhost", **not the action**. So the
page itself is the display the human trusts, and that page must not be replaceable by the agent at T2.

## Decision

- **The broker launches the UI.** `keygent ui` asks the broker to spawn `keygent-ui` (cargo feature `ui`). The broker records the child's PID and port,
  and accepts assertions only for origin `http://localhost:<that port>` **while that child is alive**. If the child dies, the origin is
  revoked. An agent that kills the UI and binds the port gets nothing. An agent that runs `keygent ui` just gets the real UI.
- **Passkey login** (ES256, `userVerification: required`, no attestation, **UP and UV flags required** in authenticatorData, sign counter checked only when non-zero (synced passkeys report 0)). The **session token lives in page memory and is
  sent as a header**, never a cookie, because cookies are shared across localhost ports. Sessions are metadata-only and last 15 min.
- **Per-action assertions:** the challenge is `H(nonce ‖ action ‖ handle ‖ params)`, single-use, 60 s. Actions: approve or deny grants, edit
  policy and allow rules, trust or untrust manifests, remove a secret, seal.
- **Excluded:** reveal, and typing secret values. Both stay in the terminal (passphrase). That removes the most damaging targets if the
  page were ever spoofed (T3), and keeps values out of the browser and its extensions.
- **Enrollment:** `keygent passkey add` needs a passphrase proof in the terminal (otherwise the agent could enroll a software
  authenticator). At least one passphrase slot always remains.
- **Front end:** static HTML, CSS and vanilla JS embedded in the binary. No CDN. CSP `default-src 'self'; frame-ancestors 'none'`.
  `Cache-Control: no-store`. Strict Host and Origin checks (DNS rebinding).
- **Passkey PRF unseal:** deferred to Phase 6.

## Consequences

- The broker gains ES256 verification and minimal CBOR (size measured in Phase 0). The HTTP parser stays out of the broker.
- T3 residual: an agent that replaces the `keygent-ui` binary on disk gets the broker to launch its fake. Mitigation: the broker
  checks the UI binary's signature (or a hash pinned at install) before spawning it, and `doctor` reports the result.
- Fuzz targets: HTTP request parser, CBOR, clientDataJSON.
