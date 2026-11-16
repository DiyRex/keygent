#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use super::*;
use crate::vault::index::{Mode, new_handle};

struct Tmp(PathBuf);
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tmp() -> (Tmp, Dirs) {
    let n: String = crypto::random::<6>()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let root = std::env::temp_dir().join(format!("kg-vault-test-{n}"));
    std::fs::create_dir_all(&root).unwrap();
    let dirs = Dirs {
        data: root.join("data"),
        config: root.join("config"),
        state: root.join("state"),
    };
    (Tmp(root), dirs)
}

fn pass() -> Secret {
    Secret::from_slice(b"orbit-canyon-velvet-anchor-mosaic-tundra")
}
fn rk() -> Secret {
    Secret::from_slice(&[0x42; 32])
}
fn canary(n: u8) -> Secret {
    Secret::new(format!("KEYGENT_CANARY_q8ZtK2mW9xLp4RvN{n:02}").into_bytes())
}

/// init + one secret "stripe/live" (version 1) + one "gh/token".
fn init_with_secrets(dirs: &Dirs) -> Vault {
    let l = lock(dirs).unwrap();
    let mut v = Vault::create(dirs, &l, &pass(), &rk()).unwrap();
    for (i, h) in ["stripe/live", "gh/token"].iter().enumerate() {
        v.index
            .handles
            .push(new_handle(h, "X", "", Mode::Approve, now()));
        v.put_entry(h, 1, &canary(u8::try_from(i).unwrap()))
            .unwrap();
    }
    v.commit(Prev::Keep).unwrap();
    v
}

fn open(dirs: &Dirs, how: Unlock<'_>) -> Result<Vault> {
    let l = lock(dirs)?;
    Vault::open(dirs, &l, how)
}

#[test]
fn create_open_read() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert_eq!(v.file.generation, 1);
    assert!(
        v.read_entry("stripe/live")
            .unwrap()
            .ct_eq(canary(0).expose())
    );
    assert!(v.read_entry("gh/token").unwrap().ct_eq(canary(1).expose()));
    let r = open(&dirs, Unlock::Recovery(&rk())).unwrap();
    assert!(r.read_entry("gh/token").unwrap().ct_eq(canary(1).expose()));
    // the canary never appears in the file in plaintext
    let raw = std::fs::read(dirs.data.join(VAULT_FILE)).unwrap();
    assert!(!raw.windows(15).any(|w| w == b"KEYGENT_CANARY_"));
}

#[test]
fn create_refuses_existing_vault() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let l = lock(&dirs).unwrap();
    assert_eq!(
        Vault::create(&dirs, &l, &pass(), &rk()).err(),
        Some(Error::VaultExists)
    );
}

#[test]
fn wrong_factors() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&Secret::from_slice(b"wrong"))).err(),
        Some(Error::WrongPassphrase)
    );
    assert_eq!(
        open(&dirs, Unlock::Recovery(&Secret::from_slice(&[1; 32]))).err(),
        Some(Error::WrongRecoveryKey)
    );
}

#[test]
fn pepper_is_required_for_passphrase_but_not_recovery() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    std::fs::remove_file(dirs.state.join(keystore::PEPPER_FILE)).unwrap();
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::PepperMissing)
    );
    assert!(open(&dirs, Unlock::Recovery(&rk())).is_ok());
    // a different pepper (vault copied to another machine) is a wrong passphrase, not a crash
    let ks = Keystore::new(&dirs.state).unwrap();
    ks.pepper_or_create().unwrap();
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::WrongPassphrase)
    );
}

fn flip(dirs: &Dirs, at: impl Fn(&[u8]) -> usize) {
    let p = dirs.data.join(VAULT_FILE);
    let mut b = std::fs::read(&p).unwrap();
    let i = at(&b);
    b[i] ^= 0x01;
    std::fs::write(&p, b).unwrap();
}

#[test]
fn header_tamper_detected() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    flip(&dirs, |_| 22); // generation
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::Damaged)
    );
}

#[test]
fn slot_param_tamper_detected() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    flip(&dirs, |_| 31 + 1 + 16 + 1); // first slot kdf_m low byte
    assert!(open(&dirs, Unlock::Passphrase(&pass())).is_err());
}

#[test]
fn entry_tamper_is_isolated() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    flip(&dirs, |b| b.len() - 1); // last entry ciphertext (entries sorted: stripe/live last)
    let v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert_eq!(v.read_entry("stripe/live").err(), Some(Error::Damaged));
    assert!(v.read_entry("gh/token").is_ok());
}

#[test]
fn old_entry_version_replay_rejected() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let old = std::fs::read(dirs.data.join(VAULT_FILE)).unwrap();
    {
        let mut v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
        v.index.get_mut("stripe/live").unwrap().version = 2;
        v.put_entry("stripe/live", 2, &canary(9)).unwrap();
        v.commit(Prev::Drop).unwrap();
    }
    // splice the old version-1 entry into the new file (an attacker with an old backup)
    let new = std::fs::read(dirs.data.join(VAULT_FILE)).unwrap();
    let (mut nf, _) = format::parse(&new).unwrap();
    let (of, _) = format::parse(&old).unwrap();
    let old_entry = of
        .entries
        .iter()
        .find(|e| e.handle == "stripe/live")
        .unwrap()
        .clone();
    nf.entries.retain(|e| e.handle != "stripe/live");
    nf.entries.push(old_entry);
    std::fs::write(dirs.data.join(VAULT_FILE), format::serialize(&nf).unwrap()).unwrap();
    let v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert_eq!(v.read_entry("stripe/live").err(), Some(Error::Damaged));
    // forging the version field doesn't help: the AAD binds it
    let (mut nf2, _) = format::parse(&std::fs::read(dirs.data.join(VAULT_FILE)).unwrap()).unwrap();
    nf2.entries
        .iter_mut()
        .find(|e| e.handle == "stripe/live")
        .unwrap()
        .version = 2;
    std::fs::write(dirs.data.join(VAULT_FILE), format::serialize(&nf2).unwrap()).unwrap();
    let v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert_eq!(v.read_entry("stripe/live").err(), Some(Error::Damaged));
}

#[test]
fn entries_swapped_between_handles_rejected() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let p = dirs.data.join(VAULT_FILE);
    let (mut f, _) = format::parse(&std::fs::read(&p).unwrap()).unwrap();
    let (a, b) = (f.entries[0].clone(), f.entries[1].clone());
    f.entries[0].ct = b.ct;
    f.entries[0].nonce = b.nonce;
    f.entries[1].ct = a.ct;
    f.entries[1].nonce = a.nonce;
    std::fs::write(&p, format::serialize(&f).unwrap()).unwrap();
    let v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert!(v.read_entry("stripe/live").is_err());
    assert!(v.read_entry("gh/token").is_err());
}

#[test]
fn prev_kept_or_dropped() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let g1 = std::fs::read(dirs.data.join(VAULT_FILE)).unwrap();
    let mut v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    v.index.get_mut("gh/token").unwrap().description = "x".into();
    v.commit(Prev::Keep).unwrap();
    assert_eq!(std::fs::read(dirs.data.join(PREV_FILE)).unwrap(), g1);
    std::fs::write(dirs.data.join("vault.kgt.pre-v0"), b"old").unwrap();
    v.commit(Prev::Drop).unwrap();
    assert!(!dirs.data.join(PREV_FILE).exists());
    assert!(!dirs.data.join("vault.kgt.pre-v0").exists());
}

#[test]
fn rollback_detected_by_tripwire() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let g1 = std::fs::read(dirs.data.join(VAULT_FILE)).unwrap();
    let mut v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    v.commit(Prev::Keep).unwrap();
    assert!(!v.rolled_back);
    drop(v);
    std::fs::write(dirs.data.join(VAULT_FILE), &g1).unwrap();
    let mut v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert!(v.rolled_back);
    // a confirmed write moves past the tripwire generation
    v.commit(Prev::Keep).unwrap();
    assert_eq!(v.file.generation, 3);
    assert!(
        !open(&dirs, Unlock::Passphrase(&pass()))
            .unwrap()
            .rolled_back
    );
}

#[test]
fn passwd_and_rekey() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let new = Secret::from_slice(b"lantern-quiver-sable-meadow-gusto-pivot");
    {
        let mut v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
        let pepper = v.keystore().pepper().unwrap().unwrap();
        let old_salt = v.file.slots[0].salt;
        v.set_passphrase(&new, &pepper).unwrap();
        assert_ne!(v.file.slots[0].salt, old_salt);
        assert_eq!(v.file.slots.len(), 2);
        v.commit(Prev::Drop).unwrap();
    }
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::WrongPassphrase)
    );
    assert!(
        open(&dirs, Unlock::Recovery(&rk())).is_ok(),
        "passwd keeps the recovery slot"
    );
    let rk2 = Secret::from_slice(&[0x43; 32]);
    {
        let mut v = open(&dirs, Unlock::Passphrase(&new)).unwrap();
        v.index
            .get_mut("stripe/live")
            .unwrap()
            .previous_version_until = Some(now() + 100);
        v.index.get_mut("stripe/live").unwrap().previous_value = Some(canary(7));
        v.rekey(&new, &rk2).unwrap();
        v.commit(Prev::Drop).unwrap();
    }
    assert_eq!(
        open(&dirs, Unlock::Recovery(&rk())).err(),
        Some(Error::WrongRecoveryKey)
    );
    let v = open(&dirs, Unlock::Recovery(&rk2)).unwrap();
    assert!(
        v.read_entry("stripe/live")
            .unwrap()
            .ct_eq(canary(0).expose())
    );
    assert!(v.index.get("stripe/live").unwrap().previous_value.is_none());
}

#[test]
fn unsafe_permissions_refused() {
    use std::os::unix::fs::PermissionsExt;
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let p = dirs.data.join(VAULT_FILE);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::UnsafePath("vault file"))
    );
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dirs.data, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::UnsafePath("keygent dir"))
    );
}

#[test]
fn symlinked_vault_refused() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    let p = dirs.data.join(VAULT_FILE);
    let real = dirs.data.join("real.kgt");
    std::fs::rename(&p, &real).unwrap();
    std::os::unix::fs::symlink(&real, &p).unwrap();
    assert_eq!(
        open(&dirs, Unlock::Passphrase(&pass())).err(),
        Some(Error::UnsafePath("vault file"))
    );
}

#[test]
fn stale_tmp_swept_and_unknown_entries_dropped() {
    let (_t, dirs) = tmp();
    init_with_secrets(&dirs);
    std::fs::write(dirs.data.join("vault.kgt.deadbeef.tmp"), b"partial").unwrap();
    let mut v = open(&dirs, Unlock::Passphrase(&pass())).unwrap();
    assert!(!dirs.data.join("vault.kgt.deadbeef.tmp").exists());
    v.file.entries.push(RawEntry {
        handle: "ghost".into(),
        version: 1,
        nonce: [0; 24],
        ct: vec![0; 20],
    });
    v.commit(Prev::Keep).unwrap();
    assert!(v.file.entries.iter().all(|e| e.handle != "ghost"));
}

#[test]
fn locks_are_exclusive() {
    let (_t, dirs) = tmp();
    let _a = lock(&dirs).unwrap();
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(dirs.data.join(LOCK_FILE))
        .unwrap();
    assert!(f.try_lock().is_err());
}

#[test]
fn symlinked_lock_file_refused() {
    let (_t, dirs) = tmp();
    drop(lock(&dirs).unwrap());
    let p = dirs.data.join(LOCK_FILE);
    std::fs::remove_file(&p).unwrap();
    std::os::unix::fs::symlink(dirs.data.join("elsewhere"), &p).unwrap();
    assert!(lock(&dirs).is_err());
}
