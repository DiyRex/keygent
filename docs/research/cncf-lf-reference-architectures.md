# Reference architectures: CNCF and Linux Foundation tools near keygent

- **Date:** 2026-11-17
- **Status:** research input to [ADR 0016](../adr/0016-reference-architectures-adoption.md)
- **Method:** four parallel source reads (docs, repos, specs). The load-bearing claims were then re-checked by fetching the
  primary source: tokenizer CONNECT refusal, CB4A PDP/CDP text, OpenShell placeholders, OpenShell driver plaintext
  `value`. Size figures marked *estimate* are unmeasured.

No CNCF or LF project covers keygent's niche: local CLI children on a developer laptop, agent-visible output redaction,
and human approval bound to the exact command and binary/script hashes. The projects below cover adjacent layers.

---

## 1. Egress credential injection: the agent holds a placeholder, never the value

### 1.1 IETF CB4A, `draft-hartman-credential-broker-4-agents-00`

An individual draft (Hartman, 2026-03-29) that expired 2026-09-30. It is not normative.
<https://datatracker.ietf.org/doc/html/draft-hartman-credential-broker-4-agents-00>

- **Model A, proxy gateway.** The broker injects credentials on egress, so the agent never holds them. The draft uses it
  mainly as a DPoP enforcement layer.
- **Model B, short-lived token minting.** Uses an STS, RFC 8693, or GitHub App tokens. This is the **RECOMMENDED
  primary model**.
- **Model C, wrap and schedule revocation.** NOT RECOMMENDED.
- **PDP/CDP split (verified):** "The component that decides 'yes' (PDP) MUST never touch credential material. The
  component that dispenses credentials (CDP) MUST never make policy decisions."
- **Audit:** "no credentials issued if audit trail is unavailable" (fail closed, verified). The log is hash-chained in a
  separate trust boundary.

### 1.2 agentgateway (LF; Rust)

<https://agentgateway.dev/blog/2026-07-27-credential-injection-ai-agent-egress-cb4a/>

- Implements Model A for LLM and MCP traffic. Injects `Authorization` by default.
- **Elicitation:** when no upstream token exists, the call fails with an authorization URL. The user consents in a
  browser, and the token is stored in an STS keyed by `(user sub, resource)`.
- At most one backend-auth mode per policy (key, passthrough, aws/gcp/azure, jwtSign, oauthTokenExchange,
  crossAppAccess).
- Stores credentials with envelope encryption (AES-GCM DEK under a KMS KEK, with AAD per row).
- The stack (tokio, hyper, rustls, aws-lc-rs, rcgen) is far heavier than keygent's budget.

### 1.3 Envoy `credential_injector` (CNCF graduated)

<https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/credential_injector_filter>

- Credential sources: `Generic` (secret plus header prefix) or OAuth2 client credentials.
- `overwrite` defaults to false. `allow_request_without_credential` controls fail-open, and its default is fail-closed.
- Envoy Gateway adds a configurable `header`.
- Lesson: injection targets declared header slots and is governed by explicit overwrite semantics.

### 1.4 Fly.io tokenizer (Go): the closest precedent

<https://github.com/superfly/tokenizer>

- Secrets are sealed to the proxy's key and sent in a `Proxy-Tokenizer` header. The client authenticates to the proxy.
- **Processors:** `inject` (dst header or `query:`, printf `fmt`), `inject_hmac`, `sigv4` re-signing, `jwt`,
  `client_credentials`, `github_app`. A client may override fields only within `allowed_dst` / `allowed_fmt`.
- **Host binding:** `allowed_hosts` / `allowed_host_pattern`.
- **CONNECT is refused (verified):** "request validators check the Host header, but a tunneled request is delivered to
  whatever the CONNECT line named".
- **SSRF guard (verified):** it denies private, loopback, unspecified and link-local destinations.
- Strips `Proxy-*` headers. Logs host, path and query *keys* only.

### 1.5 OpenShell placeholders (CNCF Sandbox): verified

<https://docs.nvidia.com/openshell/how-it-works/providers/overview>

- "OpenShell supplies each eligible provider credential as an opaque placeholder token in the agent's environment"
  (`OPENSHELL-RESOLVE-ENV-…`). The proxy resolves it right before forwarding.
- Substitution slots:
  - declared header values;
  - `query_param`;
  - `path_template`;
  - SigV4 signing;
  - bodies and WebSocket text only with an explicit endpoint policy.
- A destination that doesn't match the binding gets **HTTP 403 `credential_endpoint_mismatch`**.
- Credentials are injected *after* middleware runs, so middleware never sees them.
- Related: Deno Sandbox and the `shard` project use the same pattern (placeholder in env, real value only for
  configured hosts, single-pass substitution, ungranted placeholders map to themselves).
- Anthropic `sandbox-runtime` adds the TLS-termination option: an ephemeral CA exposed through `SSL_CERT_FILE`,
  `REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS` and `GIT_SSL_CAINFO`, with `excludeDomains` for pinned/mTLS clients.
  <https://raw.githubusercontent.com/anthropic-experimental/sandbox-runtime/main/README.md>

### 1.6 What egress can't cover

- Non-HTTP protocols: Postgres or Redis DSNs, SSH, SMTP.
- Client-side request signing (AWS SigV4, HMAC), unless the proxy re-signs.
- Certificate pinning and mTLS.
- Secrets used locally (signing or encryption keys).
- HTTP/3.
- Clients that ignore proxy or CA env vars.
  - Node needs `NODE_USE_ENV_PROXY=1` (22.21+/24+).
  - Go before 1.27 ignores `SSL_CERT_FILE` on macOS/Windows, and from 1.27 replaces the system roots with it.

All of these **fail safe** (the child only has a placeholder) but **not functionally**, so those handles keep env
injection as a T3 residual.

### 1.7 Size

A rustls client alone is about 1.4–1.7 MB (ring provider, LTO; <https://github.com/moq-dev/rind/pull/375>). That is
most of the 2 MB hard cap. MITM mode also needs a server side and certificate generation.

Options:
- the experimental `rustls-rustcrypto` provider (would need an ADR against "RustCrypto only");
- a cargo feature with its own budget;
- OS TLS via FFI.

All need a measured spike first.

---

## 2. Hook-level policy: Prempti (Falco ecosystem; Falco is CNCF graduated)

<https://github.com/falcosecurity/prempti> · <https://www.cncf.io/blog/2026/05/20/introducing-prempti-policy-and-visibility-for-ai-coding-agents/>

### Components

- **Interceptor:** a stateless Rust binary (serde only). It is a Claude Code **PreToolUse** hook with an empty matcher,
  so it sees every tool.
- **`coding_agent` Falco plugin:** a source/extract plugin (ID 28) with a built-in broker.
- **`premptictl` supervisor:** spawns Falco and **adds its hook to `~/.claude/settings.json` on start**.
- **Rules:** `rules/default` and `rules/user`.

### Flow

1. The interceptor sends a JSON line over AF_UNIX to `~/.prempti/run/broker.sock`.
2. Falco evaluates the rules and POSTs an alert to the plugin on `127.0.0.1:2802`.
3. Each rule's tag sets the verdict: `coding_agent_deny` or `coding_agent_ask`. Precedence is deny > ask >
   allow/defer.
4. A catch-all `coding_agent_seen` rule closes evaluation.
5. A `defer` verdict produces empty stdout.

### Failure and trust

- Fails closed: unreachable broker, timeout (default 5000 ms) or a full queue all deny. `PREMPTI_FAIL_OPEN=1`
  overrides this.
- Everything is denied during the 2–3 s it takes to restart.
- The alert endpoint is **unauthenticated**, which the project acknowledges.
- "Not a sandbox": it sees only *declared* commands.
- PreToolUse only. No `updatedInput`, no PostToolUse, no injection, no redaction.

### Fields

- `agent.{name, pid, session_id, permission_mode, cwd, real_cwd, real_cwd_prefix, …}`
- `tool.{use_id, name, input, input_command, file_path, real_file_path, …}`

### Default secret rules

- Lists:
  - `sensitive_file_names`: `.env`, `.env.local`, `.env.production`, `.netrc`, `.npmrc`, `credentials.json`,
    `token.json`;
  - `env_file_names`: `.env`, `.envrc`, `.env.*`;
  - credential directories: `~/.ssh`, `~/.aws`, `~/.azure`, `~/.kube`, `~/.docker`, `~/.gnupg`.
- Rules also cover other agents' OAuth files, curl/wget exfiltration and IMDS.
- Matching is done on **canonical** paths, and on both the access name and the resolved target.

### Claude Code hook composition

Matching hooks run in parallel. Decisions merge deny > ask > allow. For conflicting `updatedInput` values, the last one
wins and the conflict is logged. <https://code.claude.com/docs/en/hooks>

---

## 3. Runtime governance: OpenShell (CNCF Sandbox, 2026-11-10) and Cedar (CNCF Sandbox, 2025-10)

<https://github.com/NVIDIA/OpenShell> · <https://docs.nvidia.com/openshell/latest/>

### Components

- **Gateway:** control plane and credential store.
- **Supervisor:** trusted, outside the workload. It is the only network path out, and it checks policy and injects
  credentials.
- **Sandbox:** Landlock, seccomp and namespaces on Linux. macOS uses a microVM.
- The agent sits *inside* a kernel or VM boundary. keygent's ADR 0003 has no such boundary: the agent is the same user.

### Binary identity

Hashes the *already-open* `/proc/<pid>/exe` and a bounded chain of ancestors, and denies if any link fails.

### Policy

- Stable format is YAML: filesystem, Landlock, process, network and L7 rules (REST, GraphQL, MCP tool names).
- **Cedar** is the planned policy language, behind a feature flag and pinned to a fork.
  - Principal is `Sandbox::Process`. Actions include `NetworkConnect` and `ReadFile`.
  - Context: `binary_path`, `method`, `path`, `query`, `destination_ip`.
  - `@enforcement("audit")` stages a policy so it only logs.
  - Credential rules are compiled into Cedar.
- **Prover:** Z3-based, reporting `credential_reach_expansion`, `l7_bypass_credentialed` and similar.

### Policy Advisor (approval workflow)

<https://docs.nvidia.com/openshell/latest/how-it-works/policies/advisor.md>

- The agent proposes a rule. It is **pending** by default.
- The **requester can never approve** its own proposal.
- Auto-approval only happens when the prover finds nothing.
- The audit record carries the actor, an `auto` flag and the source (`agent_authored` or `mechanistic`).

### Credential driver

<https://github.com/NVIDIA/OpenShell/blob/main/proto/credential_driver.proto>

- gRPC methods: `GetCapabilities`, `StoreCredential`, `DeleteCredential`, `ResolveCredentials`, `ListCredentials`.
- **`ResolvedCredential.value` is plaintext returned to the gateway (verified).**

### Audit

OCSF v1.8 JSONL, with optional OTLP export.

### Cedar

<https://www.cncf.io/projects/cedar/>

- Principal / action / resource / context, validated against a schema. No loops.
- `cedar-policy-symcc` uses the CVC5 solver to check equivalence or containment between policy sets.
- **Sets, not ordered lists:** argv must be tokenized before evaluation.
- `cedar-policy` 4.x pulls in serde_json, miette, a lalrpop parser and more. *Estimate:* +1.5–3 MB, which is over
  budget.

### Agent Substrate + gVisor (CNCF Sandbox, 2026-11)

<https://github.com/agent-substrate/substrate>

- An actor is one agent session with its own SPIFFE certificate.
- The egress gateway calls `CredentialProvider.FetchSecret(uri, actor identity)`. **The provider authorizes
  independently.**
- Injection happens only on the TLS-intercepted leg, never on cleartext, and fails closed.
- Kubernetes-only; patterns only.

---

## 4. Secret backends: OpenBao (OpenSSF Sandbox)

<https://openbao.org/docs/>

### Leases

- Dynamic engines (database, PKI, SSH, …) issue a lease with a TTL that can be renewed or revoked.
- Revoking a token revokes all its leases.
- KV v2 is versioned with check-and-set writes and has **no real leases**.
- AWS, GCP and Azure engines are now external plugins.

### Response wrapping

A single-use cubbyhole token. Check the creation path with `sys/wrapping/lookup` before unwrapping. An "already
unwrapped" error means tampering.

### Auth

- OIDC uses PKCE with a loopback callback.
- AppRole uses `role_id` + `secret_id`, with use counts, TTLs, CIDR binding and lockout.

### Agent and Proxy

- Both support auto-auth and caching.
- `exec` mode puts secrets into a child's env and **passes its stdio straight through**, which means no redaction.
  That is unusable for keygent.
- `use_auto_auth_token` lets any same-user process use the token.
- Proxy's API-proxy feature is marked "will be deprecated". Verify before depending on it.

### Audit devices

They HMAC sensitive strings and **fail closed**: requests are refused if no device can log them.

### Size

| Integration | Added size | Notes |
|---|---|---|
| ureq + rustls | about +1.65 MB | rejected |
| Plain HTTP/1.1 over the Unix socket of a local `bao proxy` that owns TLS | about +20–40 KB | *estimate* |

### Related

- **SPIFFE/SPIRE (CNCF graduated):** on one desktop user, the agent and the human share a uid and can exec the same
  pinned binary. Same selectors, same SVID. **It can't tell them apart**, which agrees with ADR 0003.
- **RFC 9449 DPoP:** binds tokens to a key the broker holds. It helps only APIs that support DPoP, and it doesn't stop
  code running in the client's context (§11.4). It needs P-256 *signing*.
- **RFC 8693 token exchange / ID-JAG:** an `act` claim (for example `keygent/grant/<id>`) gives server-side visibility
  where the IdP supports it.
- **SOPS (CNCF sandbox):** values are encrypted and keys readable. `sops decrypt` can be run as a pinned program and
  piped into the broker like `capture`.
- **External Secrets Operator:** the `remoteRef {key, property, version}` shape is a model for manifest references to
  external values.
