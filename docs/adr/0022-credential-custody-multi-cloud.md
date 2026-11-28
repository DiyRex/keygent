# ADR 0022 — Dynamic credential custody: tools never hold the real secret, for any platform, tool or key

- **Status:** proposed (owner direction 2026-11-28: dynamic, no per-platform or per-tool configuration)
- **Date:** 2026-11-28
- **Verified against:** [spike 05](../spikes/05-egress-custody.md) on macOS 26 arm64 with doctl 2.11.0 (Go):
  - The rustls client adds 681,856 bytes.
  - doctl sends only `Authorization: Bearer <dummy>` to a loopback base URL.
  - doctl honours `HTTPS_PROXY` (it sends `CONNECT api.digitalocean.com:443`).
  - **doctl on macOS ignores `SSL_CERT_FILE`**: a private CA is rejected even when passed explicitly. Go uses the system verifier on macOS.
  - A base URL without a trailing `/` keeps only its first path segment (`/tok/api.digitalocean.com` → `/tok/v2/account`).
- **Builds on:** ADR 0016 A1–A3 (egress rules). ADR 0021 leases stay for non-HTTP secrets.

## Context

The owner wants the following:

- Agents run any tool for any platform (DigitalOcean, AWS, Cloudflare, Huawei, GCP, Azure, and ones not yet known) many times
  without an approval per command.
- A hostile agent (T2) still can't get the value.
- keygent has **no built-in provider or tool profiles**. It must work for platforms, tools and keys nobody listed in advance.
- The agent handles tool specifics.

## Decision

### 1. The child never holds the real value

- For a custody handle, the child's env var holds a **format-preserving dummy**, not the value. The dummy has:
  - the same length and the same character classes per position;
  - the same leading public prefix (letters followed by `_`, `-` or a digit run that the value starts with, e.g. `dop_v1_`,
    `sk_live_`, `AKIA`, `ghp_`); everything after the prefix is random.
- Tools that check the format accept the dummy. Nothing is configured per tool.
- The redactor knows both the value and the dummy.
- Custody is the default for single-line values.
  - `--no-custody` (with auth) opts out, e.g. for a database password. Those handles use leases or approvals (ADR 0021).
  - A run with a custody handle that never reaches the proxy simply fails upstream (the dummy gets a 401). That **fails
    closed**, and nothing leaks.

### 2. Two generic routes, no tool knowledge

Every run with a custody handle gets a broker-owned proxy on `127.0.0.1` and two routes into it:

- **CONNECT route.**
  - The broker sets `HTTPS_PROXY`/`HTTP_PROXY` and a per-run CA bundle in the generic trust env vars (`SSL_CERT_FILE`,
    `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`).
  - The proxy intercepts TLS only for requests that carry a dummy; everything else is tunnelled untouched.
  - Works for clients that trust an env-provided CA. *Verify per runtime*: Python, Node, curl, Go on Linux.
  - Does **not** work for Go binaries on macOS (verified).
- **Base-URL route (agent-driven).**
  - The broker sets `KEYGENT_PROXY_URL=http://127.0.0.1:<port>/<run-token>`.
  - The agent, which knows its tool, points the tool's own base-URL flag or env var at `$KEYGENT_PROXY_URL/<upstream host>/`
    (e.g. `doctl -u "$KEYGENT_PROXY_URL/api.digitalocean.com/"`).
  - If the client drops the last path segment (as doctl does without the trailing `/`), a path carrying only the run token is
    routed to the handle's single bound host.
  - This is the route for Go tools on macOS. The skill text teaches it.

### 3. Bound hosts are learned, with one human approval per (handle, host)

- The first time a dummy for handle H is seen going to host X, the proxy holds the request and asks the human:
  `allow do/token → api.digitalocean.com? (once · always)`. The prompt is broker-rendered, with the same channels as approvals.
  - **always** stores X in H's encrypted policy. Later requests to X are silent, for any tool and any arguments.
  - **deny** returns 403 and an audit record `credential_endpoint_mismatch`.
- Host rules (from ADR 0016):
  - exact normalised host; https:443 only;
  - DNS resolved in the broker, with private, loopback and link-local addresses refused;
  - no redirects followed.
- Multi-host providers (e.g. AWS regional endpoints) ask once per new host. The human may answer with a leftmost-label
  wildcard (`*.amazonaws.com`); the prompt shows that the wildcard widens the binding.

### 4. Wire schemes are detected, not configured

The proxy recognises where a dummy appears and acts by **standard wire format**:

| Where the dummy shows up | Action | Covers (examples, not profiles) |
|---|---|---|
| Any header value, or inside `Basic` base64 | swap the bytes | DigitalOcean, Cloudflare, GitHub, Stripe, OpenAI, Azure/Huawei bearer tokens, `X-Auth-Key` |
| `Authorization: AWS4-HMAC-SHA256 Credential=<dummy key id>/…` | verify the shape, **re-sign** with the real secret (incl. `STREAMING-…` chunk signatures) | AWS and every S3/SigV4-compatible API (R2, Spaces, MinIO, Huawei OBS in S3 mode) |
| `Authorization: SDK-HMAC-SHA256 Access=<dummy>…` | re-sign | Huawei Cloud AK/SK |
| `Authorization: SharedKey <account>:<sig>` with a dummy account key | re-sign | Azure Storage |
| A form field in a token request (`client_secret`, `password`, `refresh_token`) | swap in that field only; **keep the returned access token** in the broker and return a dummy token | OAuth2 client credentials, Azure Entra, Huawei IAM |
| JWT assertion signed with a dummy key | **deferred**: needs RSA signing (not in the crypto set) | GCP service-account keys → lease/approval until an ADR adds RS256 |

Anything else carrying a dummy (body, URL query, unknown signature) is **refused with 403** and audited. Substitution never
happens in request bodies except the token-request field above. New schemes are added as code for a **standard**, never
for a provider.

### 5. Approvals

- Running a command that uses a custody handle needs **no per-command approval**. The value can't leave through the child, so
  any tool, arguments, shells and pipelines are fine.
- The human approves **hosts**, once each (§3).
- Non-custody handles keep leases or approval (ADR 0021).

## Security (named tiers)

- **T1 and T2 are closed for value theft on HTTP APIs.** Env, argv, files, memory, `ps`, config edits and `-u https://evil` all
  see or send only the dummy, and unapproved hosts get 403.
- **Residual: use within the granted authority.** The agent can *use* the credential on approved hosts (e.g. delete a
  droplet). That is the authority the human granted, and it is audited.
- **Residual: local proxy use.** Same-user code can reach the run's proxy while the run lives. The run token in the path and a
  random port narrow this. This is T3 per ADR 0016 §9.
- **Residual: hostile approved host.** Prompts show the exact host. Wildcards are explicit and flagged.
- **Residual: reflection on an approved host.** An approved host that echoes a request header back (e.g. a debug endpoint)
  could return the swapped value. Every response passes the redactor, which knows the value (ADR 0016 §6), so the child sees
  the dummy again. The proxy fails closed if redaction of a response fails. Swapping is limited to header values where the
  dummy appears **whole**, never a substring of a longer token.

## Consequences

- **Size.** The TLS client lives **in the broker** (one plaintext process). Estimates: about 1.54 MB on macOS, about 1.8 MB on
  Linux x86_64, under the 2 MB cap. The CA needs P-256 **signing** (`p256` with `ecdsa`, the same RustCrypto crate) plus a
  hand-written minimal DER encoder for certificates; measure the size before adding them.
  - AGENTS.md / SPEC §4 crypto list: `p256` becomes "verify + sign (per-run egress CA only)". That is a §17 row.
- **Build steps** (each a PR with leak tests):
  - C1: proxy core, base-URL route, header swap, learned hosts.
  - C2: CONNECT route and per-run CA.
  - C3: SigV4 re-sign.
  - C4: token-request custody.
  - C5: Huawei and SharedKey re-sign.
  - GCP stays deferred.
  - Each is verified with a real CLI and recorded in a spike note.
- **Leak suite, per scheme:**
  - the dummy reaches only approved hosts;
  - `-u https://evil`, an evil host and a config edit get 403 plus audit;
  - the real value never appears in the child's env, argv, files or output;
  - a tool that ignores both routes fails closed.
- **ADR 0021 (leases)** narrows to non-HTTP secrets and `--no-custody` handles.

## As built: C1 (2026-11-28)

- **Dummies are not redacted.** They aren't secret, and their kept prefix is limited by §1. This replaces "the redactor also
  knows the dummies". When the value's letters are all hex digits, the dummy's letters are hex too, so "64 hex chars" checks
  pass.
- **Hosts are approved up front for now.** `keygent edit <h> --allow-host <host>` / `--remove-host` (passphrase), and
  `keygent ls` shows `custody → host,…`. The learned-host prompt (§3) is step C1c.
- **Response framing.** The proxy drops `Content-Length` and `Transfer-Encoding` from responses and decodes chunked bodies, then
  ends the body at connection close (redaction can change lengths). Requests get `Accept-Encoding: identity`, because a
  compressed echo would hide the value from the redactor.
- **Trust.** Roots come from the OS CA bundle at fixed paths. There is no embedded list and no env override. If no bundle
  exists, the run fails closed.
- **Audit.** One `egress` record per (decision, host, handles) is written at run end, with a request count (FORMATS §5).
  Per-request records come with audit v2 (ADR 0018).
- **Size** (release, per target): x86_64-musl is 2,051,560 B, 45,592 under the cap. C2 (P-256 signing for the per-run CA)
  needs room. The options are TLS 1.3-only (−40,792 B), a separate egress binary, or a larger cap. **Owner decision before C2.**
- **Verified:** macOS 26 and Linux (`rust:1-bookworm`). The `tests/custody.rs` e2e test covers:
  - the curl → proxy → local HTTPS API path;
  - no approval prompt;
  - the dummy in the child;
  - the value at the API;
  - the echo redacted;
  - a proxy bypass sends only the dummy;
  - egress audited;
  - host removal stops forwarding.
