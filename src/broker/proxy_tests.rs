#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests: a panic is the failure report"
)]
use super::*;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::mpsc;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const VALUE: &[u8] = b"KEYGENT_CANARY_proxyValue9xQ2mT7vL4kB";
const DUMMY: &[u8] = b"KEYGENT_CANARY_dummyValueZ1aB2cD3eF4gH";

/// A plain-TCP stand-in for the API: captures one request (head + body), then answers `reply`.
fn upstream(reply: &'static str) -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let l = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = Vec::new();
        let mut b = [0u8; 4096];
        loop {
            let n = s.read(&mut b).unwrap_or(0);
            if n == 0 {
                break;
            }
            got.extend_from_slice(&b[..n]);
            let text = String::from_utf8_lossy(&got).to_string();
            if let Some(end) = text.find("\r\n\r\n") {
                let head = &text[..end].to_ascii_lowercase();
                let body = &got[end + 4..];
                let done = if head.contains("transfer-encoding: chunked") {
                    body.ends_with(b"0\r\n\r\n")
                } else if let Some(p) = head.find("content-length: ") {
                    let n: usize = head[p + 16..]
                        .lines()
                        .next()
                        .unwrap()
                        .trim()
                        .parse()
                        .unwrap();
                    body.len() >= n
                } else {
                    true
                };
                if done {
                    break;
                }
            }
        }
        // echo the received Authorization header back in the body (reflection check)
        let text = String::from_utf8_lossy(&got).to_string();
        let auth = text
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
            .unwrap_or("")
            .to_owned();
        let body = format!("{reply} {auth}");
        let _ = write!(
            s,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tx.send(got).unwrap();
    });
    (addr, rx)
}

fn cred(handle: &str, dummy: &[u8], value: &[u8], hosts: &[&str]) -> Cred {
    Cred {
        handle: handle.into(),
        dummy: dummy.to_vec(),
        value: Secret::from_slice(value),
        hosts: hosts.iter().map(|h| (*h).to_owned()).collect(),
    }
}

struct Run {
    proxy: Proxy,
    outcomes: Arc<Mutex<Vec<Outcome>>>,
    dialed: Arc<Mutex<Vec<String>>>,
}

fn run(creds: Vec<Cred>, up: SocketAddr) -> Run {
    let outcomes = Arc::new(Mutex::new(Vec::new()));
    let dialed = Arc::new(Mutex::new(Vec::new()));
    let o = outcomes.clone();
    let d = dialed.clone();
    let redactor = Arc::new(Redactor::new([("svc/key", VALUE)]).unwrap());
    let connect: Arc<Connect> = Arc::new(move |host: &str| -> io::Result<Box<dyn Upstream>> {
        d.lock().unwrap().push(host.to_owned());
        Ok(Box::new(TcpStream::connect(up)?))
    });
    let report: Arc<Report> = Arc::new(move |x| o.lock().unwrap().push(x));
    let proxy = start(TOKEN.into(), creds, redactor, connect, report).unwrap();
    Run {
        proxy,
        outcomes,
        dialed,
    }
}

/// Send raw request bytes to the proxy; return the full response.
fn send(r: &Run, req: &[u8]) -> String {
    let url = r.proxy.url();
    let port: u16 = url
        .trim_start_matches("http://127.0.0.1:")
        .split('/')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(req).unwrap();
    let mut out = Vec::new();
    let _ = s.read_to_end(&mut out);
    String::from_utf8_lossy(&out).into_owned()
}

fn get(path: &str, extra: &[u8]) -> Vec<u8> {
    let mut v = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n").into_bytes();
    v.extend_from_slice(extra);
    v.extend_from_slice(b"\r\n");
    v
}

fn bearer(d: &[u8]) -> Vec<u8> {
    let mut v = b"Authorization: Bearer ".to_vec();
    v.extend_from_slice(d);
    v.extend_from_slice(b"\r\n");
    v
}

#[test]
fn swaps_dummy_for_value_only_toward_the_approved_host() {
    let (up, rx) = upstream("ok");
    let r = run(
        vec![cred("svc/key", DUMMY, VALUE, &["api.example.com"])],
        up,
    );
    let resp = send(
        &r,
        &get(
            &format!("/{TOKEN}/api.example.com/v2/account?x=1"),
            &bearer(DUMMY),
        ),
    );
    let got = String::from_utf8(rx.recv().unwrap()).unwrap();
    assert!(
        got.starts_with("GET /v2/account?x=1 HTTP/1.1\r\nHost: api.example.com\r\n"),
        "{got}"
    );
    assert!(got.contains(&format!(
        "Authorization: Bearer {}",
        String::from_utf8_lossy(VALUE)
    )));
    assert!(
        got.contains("Connection: close")
            && !got.contains(&String::from_utf8_lossy(DUMMY).to_string())
    );
    // the echoed value is redacted on the way back to the child
    assert!(resp.starts_with("HTTP/1.1 200 OK"), "{resp}");
    assert!(
        !resp.contains(&String::from_utf8_lossy(VALUE).to_string()),
        "{resp}"
    );
    assert!(resp.contains("‹keygent:svc/key›"), "{resp}");
    assert_eq!(*r.dialed.lock().unwrap(), vec!["api.example.com"]);
    assert_eq!(
        r.outcomes.lock().unwrap()[0],
        Outcome::Forwarded {
            host: "api.example.com".into(),
            handles: vec!["svc/key".into()]
        }
    );
}

#[test]
fn token_only_path_goes_to_the_single_approved_host() {
    // doctl drops the last base-URL segment: /<token>/v2/account
    let (up, rx) = upstream("ok");
    let r = run(
        vec![cred("svc/key", DUMMY, VALUE, &["api.example.com"])],
        up,
    );
    let _ = send(&r, &get(&format!("/{TOKEN}/v2/account"), &bearer(DUMMY)));
    let got = String::from_utf8(rx.recv().unwrap()).unwrap();
    assert!(
        got.starts_with("GET /v2/account HTTP/1.1\r\nHost: api.example.com"),
        "{got}"
    );
}

#[test]
fn dummy_toward_a_host_not_approved_for_it_is_refused() {
    let (up, _rx) = upstream("never");
    let other = b"KEYGENT_CANARY_otherDummyQ8wE7rT6yU5iO4p";
    let r = run(
        vec![
            cred("svc/key", DUMMY, VALUE, &["api.example.com"]),
            cred(
                "other/key",
                other,
                b"KEYGENT_CANARY_otherValueA1sD2fG3hJ4kL5z",
                &["evil.example.net"],
            ),
        ],
        up,
    );
    // svc/key's dummy sent to the host approved only for other/key
    let resp = send(
        &r,
        &get(&format!("/{TOKEN}/evil.example.net/steal"), &bearer(DUMMY)),
    );
    assert!(resp.starts_with("HTTP/1.1 403"), "{resp}");
    assert!(
        r.dialed.lock().unwrap().is_empty(),
        "upstream must not be dialed"
    );
    assert_eq!(
        r.outcomes.lock().unwrap()[0],
        Outcome::Refused {
            reason: "credential_endpoint_mismatch",
            handle: Some("svc/key".into()),
            host: Some("evil.example.net".into())
        }
    );
}

#[test]
fn wrong_token_and_no_approved_host_never_dial() {
    let (up, _rx) = upstream("never");
    let r = run(
        vec![cred("svc/key", DUMMY, VALUE, &["api.example.com"])],
        up,
    );
    let resp = send(&r, &get("/deadbeef/api.example.com/x", &bearer(DUMMY)));
    assert!(resp.starts_with("HTTP/1.1 404"), "{resp}");
    let r2 = run(vec![cred("svc/key", DUMMY, VALUE, &[])], up);
    let resp = send(&r2, &get(&format!("/{TOKEN}/v2/x"), &bearer(DUMMY)));
    assert!(
        resp.starts_with("HTTP/1.1 404") && resp.contains("no host is approved"),
        "{resp}"
    );
    assert!(r.dialed.lock().unwrap().is_empty() && r2.dialed.lock().unwrap().is_empty());
}

#[test]
fn basic_auth_and_whole_token_matching() {
    let (up, rx) = upstream("ok");
    let r = run(
        vec![cred("svc/key", DUMMY, VALUE, &["api.example.com"])],
        up,
    );
    let mut creds = b"user:".to_vec();
    creds.extend_from_slice(DUMMY);
    let mut hdr = b"Authorization: Basic ".to_vec();
    hdr.extend_from_slice(&b64_encode(&creds));
    hdr.extend_from_slice(b"\r\nX-Note: prefix");
    hdr.extend_from_slice(DUMMY); // glued to a longer token: not swapped
    hdr.extend_from_slice(b"\r\n");
    let _ = send(&r, &get(&format!("/{TOKEN}/api.example.com/"), &hdr));
    let got = String::from_utf8(rx.recv().unwrap()).unwrap();
    let mut want = b"user:".to_vec();
    want.extend_from_slice(VALUE);
    assert!(
        got.contains(&format!(
            "Authorization: Basic {}",
            String::from_utf8(b64_encode(&want)).unwrap()
        )),
        "{got}"
    );
    assert!(
        got.contains(&format!("X-Note: prefix{}", String::from_utf8_lossy(DUMMY))),
        "{got}"
    );
}

#[test]
fn bodies_are_forwarded_untouched() {
    for (framing, body) in [
        ("Content-Length: 11\r\n", b"hello world".to_vec()),
        (
            "Transfer-Encoding: chunked\r\n",
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".to_vec(),
        ),
    ] {
        let (up, rx) = upstream("ok");
        let r = run(
            vec![cred("svc/key", DUMMY, VALUE, &["api.example.com"])],
            up,
        );
        let mut req =
            format!("POST /{TOKEN}/api.example.com/v2/x HTTP/1.1\r\nHost: x\r\n{framing}")
                .into_bytes();
        req.extend_from_slice(&bearer(DUMMY));
        req.extend_from_slice(b"\r\n");
        req.extend_from_slice(&body);
        let resp = send(&r, &req);
        assert!(resp.starts_with("HTTP/1.1 200"), "{resp}");
        let got = rx.recv().unwrap();
        assert!(got.ends_with(&body), "{}", String::from_utf8_lossy(&got));
    }
}

#[test]
fn public_address_filter() {
    for (ip, public) in [
        ("1.1.1.1", true),
        ("127.0.0.1", false),
        ("10.0.0.1", false),
        ("192.168.1.1", false),
        ("169.254.169.254", false),
        ("100.64.0.1", false),
        ("0.0.0.0", false),
        ("2606:4700::1111", true),
        ("::1", false),
        ("fd00::1", false),
        ("fe80::1", false),
        ("::ffff:127.0.0.1", false),
    ] {
        assert_eq!(is_public(ip.parse().unwrap()), public, "{ip}");
    }
}

#[test]
fn base64_roundtrip() {
    for v in [&b""[..], b"a", b"ab", b"abc", b"user:pass:word"] {
        assert_eq!(b64_decode(&b64_encode(v)).unwrap(), v);
    }
    assert!(b64_decode(b"not base64!").is_none());
}
