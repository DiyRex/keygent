# Spike 05: egress custody, first measurements (2026-11-28)

These measurements feed [ADR 0022](../adr/0022-credential-custody-multi-cloud.md) (and ADR 0016 A1).
Machine: macOS 26 arm64, rustc 1.100.

## 1. TLS client size

I built a minimal HTTPS client crate with keygent's release profile (`opt-level = "z"`, fat LTO, `codegen-units = 1`,
`panic = "abort"`, strip). Its dependencies:

- `rustls` 0.23, `default-features = false`, features `ring`, `std`, `tls12`
- `webpki-roots` 1 (bundled roots)

| Build | Bytes |
|---|---:|
| std-only baseline (TCP connect) | 286,464 |
| + rustls/ring/webpki-roots client (handshake + one request) | 968,320 |
| **Δ** | **681,856** |

The client made a real request, `GET https://api.digitalocean.com/v2/account` with no token, and got
`HTTP/1.1 401 Unauthorized` back. That is the expected answer without credentials.

What this means for keygent:

- Projected size is about 1.54 MB on macOS arm64. On Linux x86_64 musl it is about 1.8 MB (estimate: today's 1.09 MB plus a
  slightly larger x86 Δ).
- Both stay under the 2 MB hard cap but go over the 1.5 MB target.
- This replaces ADR 0016's estimate of 1.4–1.7 MB for the client alone.

## 2. doctl through a local base-URL proxy (Mode R)

`doctl` 2.11.0 (Homebrew) was pointed at a local plain-HTTP listener: `doctl -u http://127.0.0.1:<port> -t kg_dummy_… account get`.
The listener received:

```
GET /v2/account HTTP/1.1
Host: 127.0.0.1:<port>
User-Agent: doctl/2.11.0-release (darwin arm64) godo/1.246.0
Authorization: Bearer kg_dummy_0123456789abcdef
```

What this shows:

- doctl accepts an `http://` loopback API URL and sends the token only as a bearer header.
- A proxy that swaps that one header and dials `https://api.digitalocean.com` itself has everything it needs.
- doctl never held the real token.

Exit code 2 came from the stub's `{}` reply, which is not a valid account body.

## Not yet verified (next spike items)

- AWS CLI and SDKs: re-signing SigV4 through a base-URL override (`AWS_ENDPOINT_URL`), including S3 chunked uploads.
- Azure CLI, gcloud and Huawei KooCLI: honouring `HTTPS_PROXY` plus a CA bundle passed through env (Mode C).
- Go binaries on macOS with a private CA (Mode C). This may be unreliable, so Mode R is preferred for Go tools.
- GCP service-account JWT re-signing: needs RSA signing. RSA is not in keygent's allowed crypto set, so it needs an ADR exception.
