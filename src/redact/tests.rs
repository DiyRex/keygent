#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
#![allow(clippy::cast_sign_loss, clippy::print_stderr)]

use super::*;

const C1: &[u8] = b"KEYGENT_CANARY_q8ZtK2mW9xLp4RvN7cYh";
const C2: &[u8] = b"KEYGENT_CANARY_Zz9!pQ'w\"e$r`t\\y/u";

fn red() -> Redactor {
    Redactor::new([("stripe/live", C1), ("odd/chars", C2)]).unwrap()
}

fn contains(h: &[u8], n: &[u8]) -> bool {
    h.windows(n.len()).any(|w| w == n)
}

/// Feed `input` in pieces of `step` bytes and return the full output.
fn chunked(r: &Redactor, input: &[u8], step: usize) -> Vec<u8> {
    let mut s = r.stream();
    let mut out = Vec::new();
    for c in input.chunks(step.max(1)) {
        s.push(c, &mut out);
    }
    s.finish(&mut out);
    out
}

#[test]
fn raw_and_encoded_forms_are_redacted() {
    let r = red();
    for v in [C1, C2] {
        let mut forms: Vec<Vec<u8>> = encode::variants(v)
            .into_iter()
            .map(|b| b.to_vec())
            .filter(|b| b.len() >= MIN_PATTERN)
            .collect();
        forms.dedup();
        for f in forms {
            let mut input = b"before ".to_vec();
            input.extend_from_slice(&f);
            input.extend_from_slice(b" after\n");
            let (out, hits) = r.redact_all(&input);
            assert!(hits >= 1, "{}", String::from_utf8_lossy(&f));
            assert!(!contains(&out, &f), "{}", String::from_utf8_lossy(&out));
            assert!(out.starts_with(b"before ") && out.ends_with(b" after\n"));
        }
    }
    let (out, _) = r.redact_all(b"x KEYGENT_CANARY_q8ZtK2mW9xLp4RvN7cYh y");
    assert_eq!(out, "x ‹keygent:stripe/live› y".as_bytes());
}

#[test]
fn real_base64_of_surrounding_text_is_caught_in_every_alignment() {
    let r = red();
    for pad in 0..6 {
        let mut doc = b"auth=".to_vec();
        doc.extend(std::iter::repeat_n(b'z', pad));
        doc.extend_from_slice(C1);
        doc.extend_from_slice(b";end");
        let enc = encode::base64_core(
            &doc,
            0,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        );
        let (out, hits) = r.redact_all(&enc);
        assert!(hits >= 1, "pad {pad}");
        assert!(!contains(
            &out,
            &encode::base64_core(
                C1,
                (5 + pad) % 3,
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
            )
        ));
    }
}

/// Property: for every chunking of the input, the output equals the one-shot output (no secret split across flushes
/// survives, nothing is lost).
#[test]
fn chunking_never_changes_the_result() {
    let r = red();
    let mut input = Vec::new();
    for i in 0..40u8 {
        input.extend_from_slice(b"line ");
        input.push(b'0' + i % 10);
        if i % 3 == 0 {
            input.extend_from_slice(C1);
        }
        if i % 7 == 0 {
            input.extend_from_slice(&encode::hex(C2, b"0123456789abcdef"));
        }
        input.extend_from_slice(b"\r\n");
    }
    let (whole, _) = r.redact_all(&input);
    assert!(!contains(&whole, C1));
    for step in [1, 2, 3, 5, 7, 8, 13, 31, 64, 1000] {
        assert_eq!(chunked(&r, &input, step), whole, "step {step}");
    }
}

#[test]
fn hold_back_never_emits_a_secret_prefix_early() {
    let r = red();
    let mut s = r.stream();
    let mut out = Vec::new();
    s.push(b"token: KEYGENT_CANARY_q8Zt", &mut out);
    assert_eq!(out, b"token: ", "the possible start of a match is held");
    s.push(b"K2mW9xLp4RvN7cYh done", &mut out);
    // a trailing "e" could still start a JWT ("eyJ…"), so it waits for more input or EOF
    assert_eq!(out, "token: ‹keygent:stripe/live› don".as_bytes());
    s.finish(&mut out);
    assert_eq!(out, "token: ‹keygent:stripe/live› done".as_bytes());
    // a held prefix that turns out not to match is released as soon as that's certain
    let mut s = r.stream();
    let mut out = Vec::new();
    s.push(b"KEYGENT_CANARY_q8", &mut out);
    assert!(out.is_empty());
    s.push(b"NOPE", &mut out);
    assert_eq!(out, b"KEYGENT_CANARY_q8NOPE");
}

#[test]
fn eof_redacts_a_truncated_secret() {
    let r = red();
    let (out, hits) = r.redact_all(b"cut: KEYGENT_CANARY_q8ZtK2");
    assert_eq!(
        (out.as_slice(), hits),
        ("cut: ‹keygent:stripe/live›".as_bytes(), 1)
    );
    // short ambiguous tails (< 6 bytes) are released
    let (out, _) = r.redact_all(b"x KEYG");
    assert_eq!(out, b"x KEYG");
}

#[test]
fn rotated_old_values_stay_registered() {
    let r = Redactor::new([
        ("a/b", &b"KEYGENT_CANARY_newvalue123456"[..]),
        ("a/b", b"KEYGENT_CANARY_oldvalue123456"),
    ])
    .unwrap();
    let (out, hits) = r.redact_all(b"KEYGENT_CANARY_oldvalue123456 KEYGENT_CANARY_newvalue123456");
    assert_eq!(hits, 2);
    assert_eq!(out, "‹keygent:a/b› ‹keygent:a/b›".as_bytes());
}

#[test]
fn multiline_pem_lines_and_rewraps() {
    let body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7q8ZtK2mW9xLp4RvN7cYh3JdF6gTb1QsVKEYGENTCANARY0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH";
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let pem = format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        lines.join("\n")
    );
    let r = Redactor::new([("gcp/sa", pem.as_bytes())]).unwrap();
    // one line leaked on its own
    let (out, hits) = r.redact_all(format!("leak {}\n", lines[0]).as_bytes());
    assert!(hits >= 1 && !contains(&out, lines[0].as_bytes()));
    // the body unwrapped, and re-wrapped at 76 columns
    let (out, _) = r.redact_all(body.as_bytes());
    assert!(!contains(&out, body.as_bytes()));
    let w76: Vec<&str> = body
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let (out, _) = r.redact_all(w76.join("\n").as_bytes());
    assert!(!contains(&out, w76[0].as_bytes()));
    // structural lines are not registered
    assert!(!contains(
        &r.redact_all(b"-----BEGIN PRIVATE KEY-----").0,
        "‹keygent".as_bytes()
    ));
}

#[test]
fn generic_detectors() {
    let r = Redactor::new(std::iter::empty()).unwrap();
    for (s, leak) in [
        ("key AKIAIOSFODNN7EXAMPLE end", "AKIAIOSFODNN7EXAMPLE"),
        (
            "gh ghp_0123456789abcdefghijABCDEFGHIJ012345 x",
            "ghp_0123456789abcdefghijABCDEFGHIJ012345",
        ),
        (
            concat!("stripe sk_", "live_51HxyzABCDEFGHIJKLMNOPqrst ok"),
            concat!("sk_", "live_51HxyzABCDEFGHIJKLMNOPqrst"),
        ),
        (
            "slack xoxb-1234567890-abcdefghij end",
            "xoxb-1234567890-abcdefghij",
        ),
        (
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U x",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nafter",
            "MIIabc",
        ),
    ] {
        let (out, hits) = r.redact_all(s.as_bytes());
        assert!(
            hits >= 1 && !contains(&out, leak.as_bytes()),
            "{s} → {}",
            String::from_utf8_lossy(&out)
        );
        assert!(contains(&out, "‹keygent:unknown›".as_bytes()));
        assert_eq!(chunked(&r, s.as_bytes(), 3), out, "{s}");
    }
    // ordinary text is untouched
    for s in [
        "AKIA is a prefix",
        "eyJ alone",
        "ghp_short",
        "-----BEGIN CERTIFICATE-----\nMII\n",
    ] {
        assert_eq!(r.redact_all(s.as_bytes()).0, s.as_bytes(), "{s}");
    }
}

#[test]
fn size_cap() {
    let big = vec![b'q'; 64 * 1024];
    let many: Vec<(String, Vec<u8>)> = (0..40)
        .map(|i| {
            (
                format!("h{i}"),
                [big.clone(), vec![b'0' + i as u8]].concat(),
            )
        })
        .collect();
    let r = Redactor::new(many.iter().map(|(h, v)| (h.as_str(), v.as_slice())));
    assert_eq!(r.err(), Some(BuildError::TooLarge));
    assert!(pattern_bytes(&big) > 64 * 1024 * 4);
}

/// Throughput budget: ≥ 200 MB/s (SPEC §4). Release-mode check; debug builds only smoke-test.
#[test]
fn throughput() {
    let secrets: Vec<(String, Vec<u8>)> = (0..200)
        .map(|i| {
            (
                format!("svc/k{i}"),
                format!("KEYGENT_CANARY_{i:04}_q8ZtK2mW9xLp4RvN7cYh").into_bytes(),
            )
        })
        .collect();
    let r = Redactor::new(secrets.iter().map(|(h, v)| (h.as_str(), v.as_slice()))).unwrap();
    let mut x: u64 = 0x1234_5678;
    let input: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            b" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n"[(x % 64) as usize]
        })
        .collect();
    let t = std::time::Instant::now();
    let out = chunked(&r, &input, 64 * 1024);
    let mbps = input.len() as f64 / 1e6 / t.elapsed().as_secs_f64();
    assert_eq!(out.len(), input.len());
    eprintln!("redactor throughput: {mbps:.0} MB/s");
    if !cfg!(debug_assertions) {
        assert!(mbps >= 200.0, "{mbps:.0} MB/s");
    }
}

#[test]
fn detector_hold_back_is_bounded() {
    // an endless token-shaped stream must not be held until EOF (memory + rescans) nor leak its prefix
    let r = red();
    for head in [&b"ghp_"[..], b"eyJ"] {
        let mut s = r.stream();
        let mut out = Vec::new();
        s.push(head, &mut out);
        let chunk = vec![b'a'; 16 * 1024];
        for _ in 0..64 {
            s.push(&chunk, &mut out);
        }
        assert!(
            !out.is_empty() && s.pending.len() <= MAX_DETECT + chunk.len(),
            "held {} bytes",
            s.pending.len()
        );
        s.push(b" tail", &mut out);
        s.finish(&mut out);
        assert!(contains(&out, b"\xe2\x80\xb9keygent:unknown\xe2\x80\xba"));
        assert!(
            !contains(&out, &[head, &b"aaaa"[..]].concat()),
            "token prefix leaked"
        );
        assert!(!contains(&out, b"aaaa"), "continuation past the cap leaked");
        assert!(out.ends_with(b" tail"), "streaming resumes after the token");
    }
}
