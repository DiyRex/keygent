//! Credential custody proxy (ADR 0022, step C1b): the run's child holds only dummies; this proxy puts the real value
//! into a request **only** on its way to a host the human approved for that handle.
//!
//! - Listens on `127.0.0.1:<random port>`; every request path starts with the run's random token.
//! - Route: `/<token>/<host>/<path>` (the agent points a tool's base URL at it), or `/<token>/<path>` when the run's
//!   handles have exactly one approved host (tools that drop the last base-URL segment).
//! - A dummy is swapped only where it appears **whole** in a header value (or inside `Basic` credentials). A dummy
//!   bound for a host not approved for its handle is refused (403); bodies and query strings are never touched (a
//!   dummy there is harmless: it is not the value).
//! - One request per connection (`Connection: close`), bodies forwarded as-is (`Content-Length` or chunked).
//! - The response streams back through the session redactor, so an approved host that echoes a header can't hand
//!   the value to the child.

use crate::crypto::Secret;
use crate::redact::Redactor;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;
use zeroize::Zeroizing;

const HEAD_MAX: usize = 64 * 1024;
const HEADERS_MAX: usize = 100;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
const CHUNK: usize = 16 * 1024;

/// One custody credential in a run.
pub struct Cred {
    pub handle: String,
    pub dummy: Vec<u8>,
    pub value: Secret,
    /// Hosts the human approved for this handle (lower-case).
    pub hosts: Vec<String>,
}

/// What happened to one request (audit and tests). Never holds a value.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Forwarded {
        host: String,
        handles: Vec<String>,
    },
    Refused {
        reason: &'static str,
        handle: Option<String>,
        host: Option<String>,
    },
}

/// A bidirectional upstream stream (TLS in production, plain TCP in tests).
pub trait Upstream: Read + Write + Send {}
impl<T: Read + Write + Send> Upstream for T {}

pub type Connect = dyn Fn(&str) -> io::Result<Box<dyn Upstream>> + Send + Sync;
pub type Report = dyn Fn(Outcome) + Send + Sync;

/// A running proxy; stops (and joins its accept thread) on drop.
pub struct Proxy {
    port: u16,
    token: String,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
}

impl Proxy {
    /// The base URL the child gets as `KEYGENT_PROXY_URL`.
    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}/{}", self.port, self.token)
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // wake the blocking accept
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

struct Ctx {
    token: String,
    creds: Vec<Cred>,
    redactor: Arc<Redactor>,
    connect: Arc<Connect>,
    report: Arc<Report>,
}

/// Start a proxy for one run. `token` is random per run (hex); `connect` dials `https://<host>:443`.
pub fn start(
    token: String,
    creds: Vec<Cred>,
    redactor: Arc<Redactor>,
    connect: Arc<Connect>,
    report: Arc<Report>,
) -> io::Result<Proxy> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let ctx = Arc::new(Ctx {
        token: token.clone(),
        creds,
        redactor,
        connect,
        report,
    });
    let st = stop.clone();
    let join = std::thread::Builder::new()
        .name("kg-proxy".into())
        .spawn(move || {
            for conn in listener.incoming() {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                let Ok(conn) = conn else { continue };
                let c = ctx.clone();
                // a connection we can't serve is dropped (the client sees a reset): fail closed
                let _ = std::thread::Builder::new()
                    .name("kg-proxy-conn".into())
                    .spawn(move || serve(&c, conn));
            }
        })?;
    Ok(Proxy {
        port,
        token,
        stop,
        join: Some(join),
    })
}

fn serve(ctx: &Ctx, mut client: TcpStream) {
    let _ = client.set_read_timeout(Some(IO_TIMEOUT));
    let _ = client.set_write_timeout(Some(IO_TIMEOUT));
    if let Err((status, msg, outcome)) = handle(ctx, &mut client) {
        if let Some(o) = outcome {
            (ctx.report)(o);
        }
        let body = format!("keygent: {msg}\n");
        let _ = write!(
            client,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
    }
}

type Fail = (&'static str, &'static str, Option<Outcome>);

fn fail(status: &'static str, msg: &'static str) -> Fail {
    (status, msg, None)
}

fn handle(ctx: &Ctx, client: &mut TcpStream) -> Result<(), Fail> {
    let reader = client
        .try_clone()
        .map_err(|_| fail("500 Internal Server Error", "proxy error"))?;
    let mut r = BufReader::with_capacity(CHUNK, reader);
    let head = read_head(&mut r).map_err(|_| fail("400 Bad Request", "bad request head"))?;
    let req = parse_head(&head).ok_or_else(|| fail("400 Bad Request", "bad request head"))?;
    let (host, path) =
        route(&req.target, &ctx.token, &ctx.creds).map_err(|m| fail("404 Not Found", m))?;
    let (out_head, used) = build_head(&req, &host, &path, &ctx.creds)?;
    let mut up =
        (ctx.connect)(&host).map_err(|_| fail("502 Bad Gateway", "upstream unreachable"))?;
    up.write_all(&out_head)
        .map_err(|_| fail("502 Bad Gateway", "upstream write failed"))?;
    drop(out_head);
    forward_body(&req, &mut r, &mut up)
        .map_err(|_| fail("502 Bad Gateway", "request body failed"))?;
    up.flush()
        .map_err(|_| fail("502 Bad Gateway", "upstream write failed"))?;
    (ctx.report)(Outcome::Forwarded {
        host: host.clone(),
        handles: used,
    });
    relay_response(ctx, up, client);
    Ok(())
}

/// Response back to the child, head and body through the redactor. Redaction can change lengths, so the length
/// framing is dropped (chunked bodies are decoded) and the body ends when the connection closes (HTTP/1.1 §6.3).
/// A read or write error just ends the connection (fail closed: nothing unredacted is ever written).
fn relay_response(ctx: &Ctx, up: Box<dyn Upstream>, client: &mut TcpStream) {
    let mut r = BufReader::with_capacity(CHUNK, up);
    let Ok(head) = read_head(&mut r) else { return };
    let Ok(text) = std::str::from_utf8(&head) else {
        return;
    };
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let status = lines.next().unwrap_or_default().to_owned();
    if !status.starts_with("HTTP/1.") {
        return;
    }
    let mut out_head = format!("{status}\r\n");
    let mut chunked = false;
    let mut length: Option<u64> = None;
    for l in lines.filter(|l| !l.is_empty()) {
        let Some((n, v)) = l.split_once(':') else {
            return;
        };
        let v = v.trim();
        match n.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => chunked = v.eq_ignore_ascii_case("chunked"),
            "content-length" => length = v.parse().ok(),
            "connection" | "keep-alive" => {}
            _ => out_head.push_str(&format!("{}: {v}\r\n", n.trim())),
        }
    }
    out_head.push_str("Connection: close\r\n\r\n");
    let mut stream = ctx.redactor.stream();
    let mut out = Zeroizing::new(Vec::with_capacity(CHUNK.saturating_mul(2)));
    let mut emit = |data: &[u8], out: &mut Zeroizing<Vec<u8>>| -> bool {
        out.clear();
        stream.push(data, out);
        client.write_all(out).is_ok()
    };
    if !emit(out_head.as_bytes(), &mut out) {
        return;
    }
    let mut buf = Zeroizing::new(vec![0u8; CHUNK]);
    if chunked {
        loop {
            let mut line = Vec::new();
            if r.by_ref().take(1024).read_until(b'\n', &mut line).is_err() {
                return;
            }
            let Some(size) = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split([';', '\r', '\n']).next())
                .and_then(|s| usize::from_str_radix(s.trim(), 16).ok())
            else {
                return;
            };
            if size == 0 {
                break;
            }
            let mut left = size;
            while left > 0 {
                let want = left.min(CHUNK);
                let Ok(n) = r.read(buf.get_mut(..want).unwrap_or_default()) else {
                    return;
                };
                if n == 0 || !emit(buf.get(..n).unwrap_or_default(), &mut out) {
                    return;
                }
                left = left.saturating_sub(n);
            }
            let mut crlf = [0u8; 2];
            if r.read_exact(&mut crlf).is_err() {
                return;
            }
        }
    } else {
        let mut left = length;
        loop {
            let want = left.map_or(CHUNK, |l| usize::try_from(l).unwrap_or(CHUNK).min(CHUNK));
            if want == 0 {
                break;
            }
            let n = match r.read(buf.get_mut(..want).unwrap_or_default()) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if !emit(buf.get(..n).unwrap_or_default(), &mut out) {
                return;
            }
            left = left.map(|l| l.saturating_sub(u64::try_from(n).unwrap_or(l)));
        }
    }
    out.clear();
    stream.finish(&mut out);
    let _ = client.write_all(&out);
    let _ = client.flush();
}

/// Bytes up to and including the blank line ending the head (≤ 64 KiB).
fn read_head(r: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let n = r
            .by_ref()
            .take(u64::try_from(HEAD_MAX.saturating_sub(head.len())).unwrap_or(0))
            .read_until(b'\n', &mut line)?;
        if n == 0 || !line.ends_with(b"\n") {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let blank = line == b"\r\n" || line == b"\n";
        head.extend_from_slice(&line);
        if blank {
            return Ok(head);
        }
    }
}

struct Request {
    method: String,
    target: String,
    headers: Vec<(String, Vec<u8>)>,
}

impl Request {
    fn header(&self, name: &str) -> Option<&[u8]> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

fn parse_head(head: &[u8]) -> Option<Request> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let mut first = lines.next()?.split(' ');
    let method = first.next()?;
    let target = first.next()?;
    let version = first.next()?;
    if first.next().is_some()
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || !target.starts_with('/')
        || !matches!(version, "HTTP/1.1" | "HTTP/1.0")
    {
        return None;
    }
    let mut headers = Vec::new();
    for l in lines {
        if l.is_empty() {
            continue;
        }
        let (n, v) = l.split_once(':')?;
        if n.is_empty() || !n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return None;
        }
        headers.push((n.to_owned(), v.trim().as_bytes().to_vec()));
        if headers.len() > HEADERS_MAX {
            return None;
        }
    }
    Some(Request {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
    })
}

/// `/<token>/<host>/rest` or `/<token>/rest` (single approved host) → (host, path).
fn route(target: &str, token: &str, creds: &[Cred]) -> Result<(String, String), &'static str> {
    let rest = target
        .strip_prefix('/')
        .and_then(|t| t.strip_prefix(token))
        .filter(|r| r.is_empty() || r.starts_with('/') || r.starts_with('?'))
        .ok_or("unknown proxy path — use $KEYGENT_PROXY_URL")?;
    let mut hosts: Vec<&str> = creds
        .iter()
        .flat_map(|c| c.hosts.iter().map(String::as_str))
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    if let Some(after) = rest.strip_prefix('/') {
        let seg = after.split(['/', '?']).next().unwrap_or_default();
        if let Some(h) = hosts.iter().find(|h| h.eq_ignore_ascii_case(seg)) {
            let path = after.get(seg.len()..).unwrap_or_default();
            return Ok(((*h).to_owned(), normalize_path(path)));
        }
    }
    match hosts.as_slice() {
        [only] => Ok(((*only).to_owned(), normalize_path(rest))),
        [] => Err("no host is approved for this run's secrets yet"),
        _ => {
            Err("several approved hosts — put the host after the token: $KEYGENT_PROXY_URL/<host>/")
        }
    }
}

fn normalize_path(p: &str) -> String {
    if p.is_empty() {
        "/".to_owned()
    } else if p.starts_with('?') {
        format!("/{p}")
    } else {
        p.to_owned()
    }
}

const HOP_BY_HOP: &[&str] = &[
    "host",
    // replaced by `identity`: a compressed echo would hide the value from the response redactor
    "accept-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "te",
    "upgrade",
];

/// The upstream request head with dummies swapped for values (zeroized on drop) and the handles used.
fn build_head(
    req: &Request,
    host: &str,
    path: &str,
    creds: &[Cred],
) -> Result<(Zeroizing<Vec<u8>>, Vec<String>), Fail> {
    let mut out = Zeroizing::new(Vec::with_capacity(1024));
    out.extend_from_slice(format!("{} {path} HTTP/1.1\r\nHost: {host}\r\n", req.method).as_bytes());
    let mut used: Vec<String> = Vec::new();
    for (name, value) in &req.headers {
        if HOP_BY_HOP.iter().any(|h| name.eq_ignore_ascii_case(h)) {
            continue;
        }
        let swapped = swap_header(name, value, host, creds, &mut used)?;
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&swapped);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Accept-Encoding: identity\r\nConnection: close\r\n\r\n");
    Ok((out, used))
}

fn swap_header(
    name: &str,
    value: &[u8],
    host: &str,
    creds: &[Cred],
    used: &mut Vec<String>,
) -> Result<Zeroizing<Vec<u8>>, Fail> {
    if name.eq_ignore_ascii_case("authorization")
        && let Some(b64) = value.strip_prefix(b"Basic ")
        && let Some(decoded) = b64_decode(b64.trim_ascii())
    {
        let decoded = Zeroizing::new(decoded);
        let inner = swap_bytes(&decoded, host, creds, used)?;
        if inner.as_slice() != decoded.as_slice() {
            let mut v = Zeroizing::new(b"Basic ".to_vec());
            v.extend_from_slice(&b64_encode(&inner));
            return Ok(v);
        }
    }
    swap_bytes(value, host, creds, used)
}

fn token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Replace every whole occurrence of a dummy; refuse if its handle isn't approved for `host`.
fn swap_bytes(
    v: &[u8],
    host: &str,
    creds: &[Cred],
    used: &mut Vec<String>,
) -> Result<Zeroizing<Vec<u8>>, Fail> {
    let mut out = Zeroizing::new(v.to_vec());
    for c in creds {
        let d = c.dummy.as_slice();
        if d.is_empty() {
            continue;
        }
        let mut i = 0usize;
        let mut next = Zeroizing::new(Vec::with_capacity(out.len()));
        let mut hit = false;
        while i < out.len() {
            let end = i.saturating_add(d.len());
            let whole = out.get(i..end) == Some(d)
                && (i == 0
                    || !out
                        .get(i.saturating_sub(1))
                        .copied()
                        .is_some_and(token_byte))
                && !out.get(end).copied().is_some_and(token_byte);
            if whole {
                if !c.hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
                    return Err((
                        "403 Forbidden",
                        "this secret is not approved for that host",
                        Some(Outcome::Refused {
                            reason: "credential_endpoint_mismatch",
                            handle: Some(c.handle.clone()),
                            host: Some(host.to_owned()),
                        }),
                    ));
                }
                next.extend_from_slice(c.value.expose());
                i = end;
                hit = true;
            } else {
                next.push(out.get(i).copied().unwrap_or_default());
                i = i.saturating_add(1);
            }
        }
        if hit {
            if !used.contains(&c.handle) {
                used.push(c.handle.clone());
            }
            out = next;
        }
    }
    Ok(out)
}

/// Copy the request body as framed by the client (`Content-Length` or chunked), untouched.
fn forward_body(req: &Request, r: &mut impl BufRead, up: &mut dyn Upstream) -> io::Result<()> {
    let chunked = req
        .header("transfer-encoding")
        .is_some_and(|v| v.eq_ignore_ascii_case(b"chunked"));
    if chunked {
        loop {
            let mut line = Vec::new();
            r.by_ref().take(1024).read_until(b'\n', &mut line)?;
            up.write_all(&line)?;
            let size_txt = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split([';', '\r', '\n']).next())
                .ok_or(io::ErrorKind::InvalidData)?;
            let size = usize::from_str_radix(size_txt.trim(), 16)
                .map_err(|_| io::ErrorKind::InvalidData)?;
            if size == 0 {
                // trailers until the blank line
                loop {
                    let mut t = Vec::new();
                    r.by_ref().take(8192).read_until(b'\n', &mut t)?;
                    up.write_all(&t)?;
                    if t == b"\r\n" || t == b"\n" || t.is_empty() {
                        return Ok(());
                    }
                }
            }
            copy_exact(r, up, size.saturating_add(2))?;
        }
    }
    let len = match req.header("content-length") {
        Some(v) => std::str::from_utf8(v)
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok())
            .ok_or(io::ErrorKind::InvalidData)?,
        None => 0,
    };
    copy_exact(r, up, len)
}

fn copy_exact(r: &mut impl Read, w: &mut dyn Upstream, mut n: usize) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    while n > 0 {
        let want = n.min(CHUNK);
        let got = r.read(buf.get_mut(..want).unwrap_or_default())?;
        if got == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        w.write_all(buf.get(..got).unwrap_or_default())?;
        n = n.saturating_sub(got);
    }
    Ok(())
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> Vec<u8> {
    let mut o = Vec::with_capacity(data.len().div_ceil(3).saturating_mul(4));
    for c in data.chunks(3) {
        let b = [
            c.first().copied().unwrap_or(0),
            c.get(1).copied().unwrap_or(0),
            c.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (k, s) in [18u32, 12, 6, 0].iter().enumerate() {
            if k <= c.len() {
                let idx = usize::try_from((n >> s) & 63).unwrap_or(0);
                o.push(B64.get(idx).copied().unwrap_or(b'A'));
            } else {
                o.push(b'=');
            }
        }
    }
    o
}

fn b64_decode(s: &[u8]) -> Option<Vec<u8>> {
    let s = s
        .strip_suffix(b"==")
        .or_else(|| s.strip_suffix(b"="))
        .unwrap_or(s);
    let mut o = Vec::with_capacity(s.len().saturating_mul(3) / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &ch in s {
        let v = u32::try_from(B64.iter().position(|&b| b == ch)?).ok()?;
        acc = (acc << 6) | v;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            o.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(o)
}

/// True for addresses that are fine to dial for a public API (no loopback, private, link-local, CGNAT, multicast…).
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_documentation()
                || v.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64))
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return is_public(IpAddr::V4(m));
            }
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || v.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// The OS CA bundle (root-owned, kept current by OS updates). Fixed paths only, never from env (SPEC §3).
const CA_BUNDLES: &[&str] = &[
    "/etc/ssl/cert.pem",                                 // macOS, Alpine, BSDs
    "/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // Fedora, RHEL
    "/etc/pki/tls/certs/ca-bundle.crt",                  // older RHEL, CentOS
    "/etc/ssl/ca-bundle.pem",                            // openSUSE
];

/// Parse every `CERTIFICATE` block of the first bundle found; fail closed if none yields a root.
fn system_roots() -> io::Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for path in CA_BUNDLES {
        let Ok(pem) = std::fs::read_to_string(path) else {
            continue;
        };
        let mut b64 = String::new();
        let mut inside = false;
        let mut ders = Vec::new();
        for line in pem.lines() {
            match line.trim() {
                "-----BEGIN CERTIFICATE-----" => {
                    inside = true;
                    b64.clear();
                }
                "-----END CERTIFICATE-----" => {
                    inside = false;
                    if let Some(der) = b64_decode(b64.as_bytes()) {
                        ders.push(rustls::pki_types::CertificateDer::from(der));
                    }
                }
                l if inside => b64.push_str(l),
                _ => {}
            }
        }
        let (added, _) = roots.add_parsable_certificates(ders);
        if added > 0 {
            return Ok(roots);
        }
    }
    Err(io::Error::other("no system CA bundle"))
}

/// Production connector: resolve in the broker, dial only public addresses on 443, TLS with the system roots,
/// certificate checked for `host`. No redirects are ever followed (the proxy does not interpret responses).
fn tls_connector() -> io::Result<Arc<Connect>> {
    let roots = system_roots()?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| io::Error::other("tls config"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let cfg = Arc::new(cfg);
    Ok(Arc::new(
        move |host: &str| -> io::Result<Box<dyn Upstream>> {
            let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, 443u16))?
                .find(|a| is_public(a.ip()))
                .ok_or_else(|| io::Error::other("no public address"))?;
            let tcp = TcpStream::connect_timeout(&addr, Duration::from_secs(15))?;
            tcp.set_read_timeout(Some(IO_TIMEOUT))?;
            tcp.set_write_timeout(Some(IO_TIMEOUT))?;
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| io::Error::other("bad host"))?;
            let conn = rustls::ClientConnection::new(cfg.clone(), name)
                .map_err(|_| io::Error::other("tls"))?;
            Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
        },
    ))
}

/// The connector for runs. With the `test-profile` feature only, `<state>/test-upstream` (`<port>`) and
/// `<state>/test-upstream-ca.pem` redirect every host to `127.0.0.1:<port>` trusting only that CA, so end-to-end
/// tests can stand in for a real API. Release builds never read these files.
pub fn connector(state: &std::path::Path) -> io::Result<Arc<Connect>> {
    #[cfg(feature = "test-profile")]
    if let Ok(port) = std::fs::read_to_string(state.join("test-upstream")) {
        return test_connector(port.trim(), &state.join("test-upstream-ca.pem"));
    }
    let _ = state;
    tls_connector()
}

#[cfg(feature = "test-profile")]
fn test_connector(port: &str, ca: &std::path::Path) -> io::Result<Arc<Connect>> {
    let port: u16 = port
        .parse()
        .map_err(|_| io::Error::other("test-upstream port"))?;
    let pem = std::fs::read_to_string(ca)?;
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = b64_decode(b64.as_bytes()).ok_or_else(|| io::Error::other("test ca"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(der))
        .map_err(|_| io::Error::other("test ca"))?;
    let cfg = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| io::Error::other("tls config"))?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    Ok(Arc::new(
        move |host: &str| -> io::Result<Box<dyn Upstream>> {
            let tcp = TcpStream::connect(("127.0.0.1", port))?;
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| io::Error::other("bad host"))?;
            let conn = rustls::ClientConnection::new(cfg.clone(), name)
                .map_err(|_| io::Error::other("tls"))?;
            Ok(Box::new(rustls::StreamOwned::new(conn, tcp)))
        },
    ))
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
