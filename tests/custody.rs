//! Credential custody end to end (ADR 0022, step C1d): a real HTTPS server stands in for an API. The child gets only a
//! dummy and `KEYGENT_PROXY_URL`; the broker's proxy sends the real value only to the approved host.
//!
//! Needs `openssl`, `python3` and `curl` on the machine (skipped with a note otherwise). Run with
//! `cargo test --features test-profile --test custody`.
#![cfg(feature = "test-profile")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::print_stderr,
    reason = "tests: a panic is the failure report"
)]

mod common;
use common::*;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn have(tool: &str) -> bool {
    ["/usr/bin", "/bin", "/opt/homebrew/bin", "/usr/local/bin"]
        .iter()
        .any(|d| Path::new(d).join(tool).exists())
}

/// A throwaway CA and a `localhost` leaf signed by it (outside the keygent root).
fn certs(dir: &Path) {
    let sh = format!(
        "cd '{}' && \
         openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 1 \
           -subj '/CN=keygent test CA' -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign' && \
         openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout leaf.key -out leaf.csr -subj '/CN=localhost' && \
         printf 'subjectAltName=DNS:localhost\\nextendedKeyUsage=serverAuth\\n' > ext && \
         openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out leaf.pem -days 1 -extfile ext",
        dir.display()
    );
    let ok = Command::new("/bin/sh")
        .args(["-c", &sh])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok, "openssl failed");
}

const SERVER: &str = r#"
import http.server, ssl, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        a = self.headers.get('Authorization', '')
        with open(sys.argv[3], 'a') as f:
            f.write(self.path + ' ' + a + '\n')
        body = ('auth=' + a).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(('127.0.0.1', 0), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
print(srv.server_address[1], flush=True)
srv.serve_forever()
"#;

/// The stand-in API: returns (process, port, path of its request log).
fn api(dir: &Path) -> (Child, u16, PathBuf) {
    let log = dir.join("seen.txt");
    let mut c = Command::new("python3")
        .args(["-c", SERVER])
        .arg(dir.join("leaf.pem"))
        .arg(dir.join("leaf.key"))
        .arg(&log)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(c.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    (c, line.trim().parse().unwrap(), log)
}

struct Killed(Child);
impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn custody_sends_the_value_only_to_the_approved_host() {
    if !["openssl", "python3", "curl"].iter().all(|t| have(t)) {
        eprintln!("skip: needs openssl, python3 and curl");
        return;
    }
    let side = Root::new(); // the "internet": certs and the API's request log, outside the keygent root
    certs(&side.0);
    let (server, port, seen) = api(&side.0);
    let _server = Killed(server);

    let root = Root::new();
    init(&root);
    let c = canary();
    assert_eq!(add(&root, "do/token", &c).0, 0);
    let (code, _, err) = run(
        &root,
        &["edit", "do/token", "--allow-host", "localhost"],
        &[PASS, "y"],
    );
    assert_eq!(code, 0, "{err}");
    let (_, out, _) = run(&root, &["unseal"], &[PASS]);
    assert!(out.is_empty());
    let (_, out, _) = run(&root, &["ls"], &[]);
    assert_eq!(out, "do/token  $DO_TOKEN  approve  custody → localhost\n");
    // test-profile only: the proxy dials this local server for any host, trusting only its CA
    std::fs::write(root.0.join("state/test-upstream"), port.to_string()).unwrap();
    std::fs::copy(
        side.0.join("ca.pem"),
        root.0.join("state/test-upstream-ca.pem"),
    )
    .unwrap();
    let proj = root.0.join("proj");
    std::fs::create_dir_all(proj.join(".git")).unwrap();

    // 1. no approval prompt; the child holds a dummy; the API receives the real value; the echo comes back redacted
    let cmd = "T={{keygent:do/token}} sh -c 'printf \"dummy=%s\\n\" \"$T\"; \
               curl -s \"$KEYGENT_PROXY_URL/localhost/v2/account\" -H \"Authorization: Bearer $T\"'";
    let (code, out, err) = Session::start_cmd({
        let mut x = common::cmd(&root, &["run", "--", cmd]);
        x.current_dir(&proj);
        x
    })
    .finish();
    assert_eq!(code, 0, "{err}");
    let dummy = out
        .lines()
        .next()
        .and_then(|l| l.strip_prefix("dummy="))
        .unwrap()
        .to_owned();
    assert_eq!(dummy.len(), c.len());
    assert_ne!(dummy, c);
    assert!(
        out.contains("auth=Bearer ‹keygent:do/token›"),
        "the API's echo of the value is redacted: {out}"
    );
    let log = std::fs::read_to_string(&seen).unwrap();
    assert_eq!(
        log,
        format!("/v2/account Bearer {c}\n"),
        "API got the value"
    );

    // 2. a tool that bypasses the proxy only ever sends the dummy
    let bypass = format!(
        "T={{{{keygent:do/token}}}} sh -c 'curl -sk https://localhost:{port}/direct -H \"Authorization: Bearer $T\"'"
    );
    let (code, _, err) = Session::start_cmd({
        let mut x = common::cmd(&root, &["run", "--", &bypass]);
        x.current_dir(&proj);
        x
    })
    .finish();
    assert_eq!(code, 0, "{err}");
    let log = std::fs::read_to_string(&seen).unwrap();
    let direct = log.lines().find(|l| l.starts_with("/direct")).unwrap();
    assert!(!direct.contains(&c), "bypass leaked the value: {direct}");

    // 3. every proxied request is audited (host, handle, count); no file under the root holds the value
    let audit = std::fs::read_to_string(root.0.join("state/audit.jsonl")).unwrap();
    assert!(
        audit.contains("\"event\":\"egress\"")
            && audit.contains("\"decision\":\"forwarded\"")
            && audit.contains("\"host\":\"localhost\"")
            && audit.contains("\"requests\":1"),
        "{audit}"
    );
    assert_no_plaintext(&root, &c);

    // 4. with the host removed, nothing is forwarded
    let (code, _, err) = run(
        &root,
        &["edit", "do/token", "--remove-host", "localhost"],
        &[PASS, "y"],
    );
    assert_eq!(code, 0, "{err}");
    let before = std::fs::read_to_string(&seen).unwrap();
    let (code, out, err) = Session::start_cmd({
        let mut x = common::cmd(&root, &["run", "--", cmd]);
        x.current_dir(&proj);
        x
    })
    .finish();
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("no host is approved"), "{out}");
    assert_eq!(std::fs::read_to_string(&seen).unwrap(), before);
}
