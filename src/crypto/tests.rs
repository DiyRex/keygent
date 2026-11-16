#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Golden vectors (tests/golden/crypto/vectors.txt): `name = hex` lines. They pin the exact derivations of SPEC §5.2
/// so a refactor can never silently change key derivation.
fn golden(name: &str) -> String {
    let file = include_str!("../../tests/golden/crypto/vectors.txt");
    file.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(name).and_then(|r| r.strip_prefix(" = ")))
        .unwrap_or_else(|| panic!("missing golden {name}"))
        .to_owned()
}

const UUID: [u8; 16] = *b"0123456789abcdef";
const SALT: [u8; 16] = *b"slot-salt-000001";

#[test]
fn enc_is_length_prefixed() {
    assert_eq!(
        hex(&enc(&[b"ab", b""]).unwrap()),
        "020000006162".to_owned() + "00000000"
    );
    // plain concatenation of ("a","bc") and ("ab","c") must differ
    assert_ne!(*enc(&[b"a", b"bc"]).unwrap(), *enc(&[b"ab", b"c"]).unwrap());
}

#[test]
fn golden_derivations() {
    let pass = Secret::from_slice(b"correct-horse-battery-staple-orbit");
    let pepper = Secret::from_slice(&[7u8; 32]);
    let argon = argon2id(pass.expose(), &SALT, KDF_DEFAULT).unwrap();
    assert_eq!(hex(argon.expose()), golden("argon2id_m65536_t3_p4"));
    let kek = kek_passphrase(&UUID, &argon, &pepper).unwrap();
    assert_eq!(hex(kek.expose()), golden("kek_passphrase"));
    let rk = Secret::from_slice(&[9u8; 32]);
    assert_eq!(
        hex(kek_recovery(&UUID, &rk).unwrap().expose()),
        golden("kek_recovery")
    );
    let dek = Dek::from_bytes([1u8; 32]);
    for (lbl, name) in [
        (label::ENTRY, "k_entry"),
        (label::INDEX, "k_index"),
        (label::HDR, "k_hdr"),
        (label::AUDIT, "k_audit"),
        (label::AUTH, "k_auth"),
        (label::BROKER, "k_broker"),
    ] {
        assert_eq!(
            hex(subkey(&UUID, &dek, lbl).unwrap().expose()),
            golden(name),
            "{name}"
        );
    }
}

#[test]
fn pepper_changes_kek() {
    let argon = Secret::from_slice(&[3u8; 32]);
    let a = kek_passphrase(&UUID, &argon, &Secret::from_slice(&[1u8; 32])).unwrap();
    let b = kek_passphrase(&UUID, &argon, &Secret::from_slice(&[2u8; 32])).unwrap();
    assert_ne!(a.expose(), b.expose());
}

#[test]
fn kdf_caps_rejected_before_work() {
    for p in [
        KdfParams {
            m_kib: KDF_M_MAX_KIB + 1,
            t: 3,
            p: 4,
        },
        KdfParams {
            m_kib: 65_536,
            t: 0,
            p: 4,
        },
        KdfParams {
            m_kib: 65_536,
            t: 11,
            p: 4,
        },
        KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 0,
        },
        KdfParams {
            m_kib: 65_536,
            t: 3,
            p: 9,
        },
        KdfParams {
            m_kib: 16,
            t: 3,
            p: 4,
        },
    ] {
        assert!(argon2id(b"x", &SALT, p).is_err(), "{p:?}");
    }
}

#[test]
fn aead_rejects_tamper_wrong_key_and_aad() {
    let k = [5u8; 32];
    let n = [6u8; 24];
    let ct = seal(&k, &n, b"aad", b"KEYGENT_CANARY_aead").unwrap();
    assert_eq!(
        open(&k, &n, b"aad", &ct).ok().unwrap().expose(),
        b"KEYGENT_CANARY_aead"
    );
    assert!(open(&[4u8; 32], &n, b"aad", &ct).is_err());
    assert!(open(&k, &n, b"aaD", &ct).is_err());
    let mut t = ct.clone();
    t[0] ^= 1;
    assert!(open(&k, &n, b"aad", &t).is_err());
    assert!(open(&k, &n, b"aad", &ct[..ct.len() - 1]).is_err());
}

#[test]
fn hmac_verify_constant_time_api() {
    let k = Subkey::from_bytes([2u8; 32]);
    let tag = hmac(&k, b"header").unwrap();
    assert!(hmac_verify(&k, b"header", &tag));
    assert!(!hmac_verify(&k, b"headeR", &tag));
    assert!(!hmac_verify(&k, b"header", &tag[..31]));
}

#[test]
fn secret_new_keeps_bytes() {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"KEYGENT_CANARY_x");
    let s = Secret::new(v);
    assert_eq!(s.expose(), b"KEYGENT_CANARY_x");
    assert!(s.ct_eq(b"KEYGENT_CANARY_x"));
    assert!(!s.ct_eq(b"KEYGENT_CANARY_y"));
}

#[test]
fn random_below_in_range() {
    for _ in 0..1000 {
        assert!(random_below(7776).unwrap() < 7776);
    }
    assert!(random_below(0).is_err());
}
