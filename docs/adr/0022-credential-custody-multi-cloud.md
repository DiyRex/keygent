# ADR 0022 — Credential custody for cloud APIs: the tool never holds the real secret

- **Status:** proposed
- **Date:** 2026-11-28
- **Verified against:** [spike 05](../spikes/05-egress-custody.md): rustls client +681,856 bytes; doctl 2.11.0 sends only a
  bearer header to a loopback base URL. Everything marked *verify* below is unverified.
- **Builds on:** ADR 0016 A1–A3 (egress design, modes R/C, host binding), ADR 0021 (leases).

## Context

The owner wants agents to run cloud tools (DigitalOcean, AWS, Cloudflare, Huawei Cloud, GCP, Azure, …) many times without
an approval per command. A hostile agent (T2) must still be unable to get the secret.

Leases (ADR 0021) leave a T2 gap whenever the tool itself holds the real secret: endpoint flags, config files, and the tool's
own features. The only structural fix is that **the child never receives the real secret**:

- the child gets a dummy;
- a broker-owned proxy adds the real credential only on requests to the handle's bound hosts.

ADR 0016 planned this for Phase 6. This ADR moves it up and covers the auth schemes the major clouds actually use.

## Decision

### 1. Model

A custody handle has three parts:

- `scheme`: how the credential appears on the wire;
- `hosts`: the exact hosts, or leftmost-label wildcards, that may receive it;
- `mode`: `R` (base URL) or `C` (proxy + private CA, opt-in).

The child gets dummy credentials in the tool's normal env vars, and sometimes the proxy URL as a base-URL override. The
proxy, inside the broker, swaps or re-signs only on a bound host. Dummies seen going to any other host get a **403**, and the
attempt is audited as `credential_endpoint_mismatch`. The redactor also knows the dummies.

### 2. Scheme adapters

Adapters are per **scheme**, not per tool. Built-in provider profiles fill in hosts and env names.

| Scheme | Providers (profiles) | What the proxy does | Crypto | Status |
|---|---|---|---|---|
| `header` | DigitalOcean, Cloudflare API token / `X-Auth-Key`, GitHub, Stripe, OpenAI, Anthropic | swap the dummy in a declared header slot | none | doctl verified (spike 05) |
| `sigv4` | AWS (all services incl. S3), plus S3-compatible endpoints (DO Spaces, Cloudflare R2) | verify the dummy signature shape, then **re-sign** with the real secret for the real host (S3 chunked: re-sign every chunk) | HMAC-SHA256 (allowed set) | *verify* AWS CLI/SDK with `AWS_ENDPOINT_URL` |
| `hmac-huawei` | Huawei Cloud AK/SK (`SDK-HMAC-SHA256`) | re-sign | HMAC-SHA256 | *verify* |
| `token-exchange` | Azure client secret (Entra token endpoint), Huawei IAM password, OAuth refresh tokens | swap the secret only in the token request to the bound token endpoint; **keep the returned access token in the broker**; give the child a dummy access token, swapped on later requests to the bound API hosts | none | *verify* az CLI (Mode C) |
| `jwt-assertion` | GCP service-account key | the child signs with a dummy key; the proxy **re-signs** the JWT assertion sent to `oauth2.googleapis.com`; then as `token-exchange` | RSA-SHA256 (**not** in the allowed set → needs an ADR exception or a broker-minted token, ADR 0016 A4) | *verify* gcloud |
| `azure-sharedkey` | Azure Storage account key | re-sign the `SharedKey` header | HMAC-SHA256 | later |
| *(none)* | Database passwords, SSH keys, other non-HTTP | no custody | — | leases or approvals (ADR 0021) |

### 3. Routing

- **Mode R first.** Where the tool accepts a base URL (doctl `--api-url`, AWS `AWS_ENDPOINT_URL`, many SDK `*_BASE_URL`
  vars), the broker sets it to `http://127.0.0.1:<port>/<run-token>` and dials TLS itself. No CA is involved, and it is the
  most reliable mode for Go binaries.
- **Mode C** is opt-in per handle, for tools without a base-URL override (*verify* az, gcloud, Huawei KooCLI).
  - It uses an ephemeral, name-constrained CA, passed to the child only through env (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`,
    `AWS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `CURL_CA_BUNDLE`, `CLOUDSDK_CORE_CUSTOM_CA_CERTS_FILE`).
  - The CA is never installed in an OS trust store.
- All other ADR 0016 rules apply:
  - exact host binding and https:443 only;
  - DNS is resolved in the broker, with private/loopback addresses refused;
  - no redirects;
  - header-slot substitution only, never in request bodies. The one exception is the `token-exchange` form field, and only
    on its bound token endpoint.

### 4. What this does to approvals

- A custody handle needs **one approval per project and scheme**, e.g. "do/token may reach api.digitalocean.com from
  ~/proj". It holds until seal (or a lease length).
- Any tool, any arguments, shells and pipelines may use it, because nothing they can see or send anywhere else is the secret.
- Non-custody handles keep leases (ADR 0021) or per-command approval.

## Security (named tiers)

- **T1, T2:**
  - The value is never in the child's env, argv, files or memory, so dumping, printing, `-u https://evil` and editing the
    config all yield only a dummy.
  - **Residual:** the agent can *use* the credential against its bound hosts while the approval lasts. Example: delete
    droplets with the DO token. That is the authority the human granted, and it is audited; a value leak is no longer
    possible.
  - `token-exchange` access tokens stay in the broker too.
- **T3:**
  - Same-user code can still drive the proxy within scope and time ("use", not "steal"), as ADR 0016 §9 says.
  - A compromised broker is out of scope.

## Consequences

- **Size:** the rustls client is +682 KB.
  - Built into the broker (one plaintext process, preferred), keygent is about 1.54 MB on macOS and about 1.8 MB on Linux
    x86_64 (estimate). That is under the 2 MB cap and over the 1.5 MB target.
  - Alternative: a separate verified `keygent-egress` binary. That keeps the core small but makes a second process that holds
    secrets.
  - **Owner decision needed.**
- **Crypto:**
  - `sigv4`, `hmac-huawei` and `azure-sharedkey` need only HMAC/SHA-256, which is in the allowed set.
  - `jwt-assertion` needs RSA signing, which needs an exception (RustCrypto `rsa`, measured first) or minted tokens.
  - Mode C needs certificate generation (P-256 signing, today verify-only). That needs an ADR change to the crypto list.
- **Build order (each step is a small PR with leak tests):**
  1. proxy core + `header` scheme (DO, Cloudflare, GitHub, Stripe, OpenAI) in Mode R;
  2. `sigv4` (AWS, S3-compatible);
  3. `token-exchange` (Azure, Huawei IAM);
  4. `hmac-huawei`;
  5. Mode C;
  6. `jwt-assertion` (GCP).

  Each provider profile ships with a spike note recording the CLI version actually tested.
- **Leak suite:** for every scheme, the dummy reaches only the bound host. `-u`, an evil host or a config edit gets a 403 and
  an audit record. The real value never appears in the child's env or output.
