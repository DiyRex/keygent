//! The vault (SPEC §5.2, FORMATS §1–2): opening with a passphrase or recovery key, entries, index, atomic writes,
//! `.prev`, rollback tripwire, locking.
//!
//! Invariants:
//! - Every read-modify-write holds an exclusive `File::lock` on `vault.kgt.lock` for its whole duration.
//! - Writes go temp → full sync → rename → dir sync. On failure the original stays intact.
//! - `.prev` keeps the previous file, except after factor changes, removals and security-tightening changes, which
//!   delete `.prev` and every `.pre-v<N>` once the new file is durable.
//! - An entry decrypts only if its version equals the index version for that handle (no replay from `.prev`/backups).
//! - The header MAC is verified on every open; any failure fails closed with `Damaged`.
//! - Values stay in `Secret`s; nothing here logs or formats them.

pub mod audit;
pub mod format;
pub mod index;
pub mod keystore;
pub mod migrate;
pub mod names;
pub mod strength;

use crate::crypto::{self, Dek, KdfParams, Secret, Subkey};
use crate::error::{Error, Result};
use crate::platform::{self, Dirs, Platform};
use format::{RawEntry, Slot, SlotKind, VaultFile};
use index::Index;
use keystore::Keystore;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const VAULT_FILE: &str = "vault.kgt";
pub const PREV_FILE: &str = "vault.kgt.prev";
pub const LOCK_FILE: &str = "vault.kgt.lock";

/// How the caller proves itself.
pub enum Unlock<'a> {
    Passphrase(&'a Secret),
    Recovery(&'a Secret),
}

/// What to do with `vault.kgt.prev` on commit (SPEC §5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prev {
    Keep,
    /// Factor change, removal or security-tightening: drop `.prev` and `.pre-v<N>`.
    Drop,
}

/// Argon2id parameters for new passphrase slots. Test builds may use cheap parameters, and only when
/// `KEYGENT_TEST_FAST_KDF` is set under the `test-profile` feature.
pub fn kdf_params() -> KdfParams {
    if cfg!(test) || fast_kdf_requested() {
        KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        }
    } else {
        crypto::KDF_DEFAULT
    }
}

fn fast_kdf_requested() -> bool {
    #[cfg(feature = "test-profile")]
    {
        std::env::var_os("KEYGENT_TEST_FAST_KDF").is_some()
    }
    #[cfg(not(feature = "test-profile"))]
    {
        false
    }
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Data dir checks shared by every entry point: owner-only, not on a network/sync filesystem.
fn prepare_data_dir(dirs: &Dirs) -> Result<()> {
    let os = platform::os();
    os.ensure_private_dir(&dirs.data)?;
    if os.is_network_or_sync(&dirs.data)? {
        return Err(Error::NetworkFs);
    }
    Ok(())
}

/// Exclusive lock for the whole command (released on drop).
pub struct Lock {
    _f: File,
}

pub fn lock(dirs: &Dirs) -> Result<Lock> {
    prepare_data_dir(dirs)?;
    let p = dirs.data.join(LOCK_FILE);
    let os = platform::os();
    // Lock the very handle whose owner/mode was verified (O_NOFOLLOW); never reopen by path. flock works on a
    // read-only descriptor.
    let f = match os.open_private(&p)? {
        Some(f) => f,
        None => match os.create_private(&p) {
            Ok(f) => f,
            // lost a creation race: the other process's file must pass the same checks
            Err(_) => os.open_private(&p)?.ok_or(Error::UnsafePath("lock file"))?,
        },
    };
    f.lock()?;
    platform::sweep_tmp(&dirs.data);
    Ok(Lock { _f: f })
}

/// Read the vault bytes (size-capped before reading). `None` if there is no vault.
pub fn read_file(path: &Path) -> Result<Option<Vec<u8>>> {
    let Some(f) = platform::os().open_private(path)? else {
        return Ok(None);
    };
    let len = f.metadata()?.len();
    if len > format::MAX_FILE_LEN {
        return Err(Error::Damaged);
    }
    let mut b = Vec::with_capacity(usize::try_from(len).map_err(|_| Error::Damaged)?);
    f.take(format::MAX_FILE_LEN.saturating_add(1))
        .read_to_end(&mut b)?;
    if u64::try_from(b.len()).map_err(|_| Error::Damaged)? > format::MAX_FILE_LEN {
        return Err(Error::Damaged);
    }
    Ok(Some(b))
}

struct Keys {
    dek: Dek,
    entry: Subkey,
    index: Subkey,
    hdr: Subkey,
}

impl Keys {
    fn derive(uuid: &[u8; 16], dek: Dek) -> Result<Keys> {
        Ok(Keys {
            entry: crypto::subkey(uuid, &dek, crypto::label::ENTRY)?,
            index: crypto::subkey(uuid, &dek, crypto::label::INDEX)?,
            hdr: crypto::subkey(uuid, &dek, crypto::label::HDR)?,
            dek,
        })
    }
}

/// An unlocked vault held by the CLI during an auth flow (Phase 1: the vault is always sealed otherwise).
pub struct Vault {
    pub file: VaultFile,
    pub index: Index,
    keys: Keys,
    dirs: Dirs,
    keystore: Keystore,
    original: Vec<u8>,
    /// Highest generation the tripwire has seen (≥ file.generation after a confirmed rollback).
    tripwire_gen: u64,
    /// True if the tripwire shows a newer generation than this file (rolled back?).
    pub rolled_back: bool,
}

fn new_passphrase_slot(
    uuid: &[u8; 16],
    pass: &Secret,
    pepper: &Secret,
    kdf: KdfParams,
    dek: &Dek,
) -> Result<Slot> {
    let mut s = Slot {
        kind: SlotKind::Passphrase as u8,
        slot_id: crypto::random()?,
        kdf_id: 1,
        kdf: kdf.check()?,
        salt: crypto::random()?,
        nonce: crypto::random()?,
        wrapped: [0; format::WRAPPED_LEN],
    };
    let argon = crypto::argon2id(pass.expose(), &s.salt, kdf)?;
    let kek = crypto::kek_passphrase(uuid, &argon, pepper)?;
    let w = crypto::wrap_dek(&kek, &s.nonce, &s.aad(uuid)?, dek)?;
    s.wrapped = w.try_into().map_err(|_| Error::Internal(30))?;
    Ok(s)
}

fn new_recovery_slot(uuid: &[u8; 16], rk: &Secret, dek: &Dek) -> Result<Slot> {
    let mut s = Slot {
        kind: SlotKind::Recovery as u8,
        slot_id: crypto::random()?,
        kdf_id: 0,
        kdf: KdfParams {
            m_kib: 0,
            t: 0,
            p: 0,
        },
        salt: crypto::random()?,
        nonce: crypto::random()?,
        wrapped: [0; format::WRAPPED_LEN],
    };
    let kek = crypto::kek_recovery(uuid, rk)?;
    let w = crypto::wrap_dek(&kek, &s.nonce, &s.aad(uuid)?, dek)?;
    s.wrapped = w.try_into().map_err(|_| Error::Internal(31))?;
    Ok(s)
}

impl Vault {
    pub fn path(dirs: &Dirs) -> PathBuf {
        dirs.data.join(VAULT_FILE)
    }

    pub fn exists(dirs: &Dirs) -> bool {
        Self::path(dirs).exists()
    }

    /// `init`: a new vault with a passphrase slot and a recovery slot. Fails if a vault exists.
    pub fn create(dirs: &Dirs, _lock: &Lock, pass: &Secret, rk: &Secret) -> Result<Vault> {
        if Self::path(dirs).exists() {
            return Err(Error::VaultExists);
        }
        let keystore = Keystore::new(&dirs.state)?;
        let pepper = keystore.pepper_or_create()?;
        let uuid: [u8; 16] = crypto::random()?;
        let dek = crypto::new_dek()?;
        let slots = vec![
            new_passphrase_slot(&uuid, pass, &pepper, kdf_params(), &dek)?,
            new_recovery_slot(&uuid, rk, &dek)?,
        ];
        let file = VaultFile {
            uuid,
            generation: 0,
            slots,
            header_mac: [0; 32],
            index_nonce: [0; 24],
            index_ct: Vec::new(),
            entries: Vec::new(),
        };
        Ok(Vault {
            file,
            index: Index::new(crypto::random()?),
            keys: Keys::derive(&uuid, dek)?,
            dirs: dirs.clone(),
            keystore,
            original: Vec::new(),
            tripwire_gen: 0,
            rolled_back: false,
        })
    }

    /// Open the vault at the standard path.
    pub fn open(dirs: &Dirs, _lock: &Lock, how: Unlock<'_>) -> Result<Vault> {
        let bytes = read_file(&Self::path(dirs))?.ok_or(Error::NoVault)?;
        let bytes = migrate::migrate_if_needed(&dirs.data, bytes)?;
        Self::open_bytes(dirs, bytes, how)
    }

    /// Open vault bytes from anywhere (the live file or a backup for `restore`).
    pub fn open_bytes(dirs: &Dirs, bytes: Vec<u8>, how: Unlock<'_>) -> Result<Vault> {
        let (file, _) = format::parse(&bytes)?;
        let keystore = Keystore::new(&dirs.state)?;
        let dek = unwrap(&file, &keystore, how)?;
        Self::with_dek(dirs, bytes, dek)
    }

    /// Open the live vault with a DEK handed over at unseal (the broker). Header MAC and index are verified.
    pub fn open_with_dek(dirs: &Dirs, dek: Dek) -> Result<Vault> {
        let bytes = read_file(&Self::path(dirs))?.ok_or(Error::NoVault)?;
        Self::with_dek(dirs, bytes, dek)
    }

    fn with_dek(dirs: &Dirs, bytes: Vec<u8>, dek: Dek) -> Result<Vault> {
        let (file, header_len) = format::parse(&bytes)?;
        let keystore = Keystore::new(&dirs.state)?;
        let keys = Keys::derive(&file.uuid, dek)?;
        let hdr = bytes.get(..header_len).ok_or(Error::Damaged)?;
        if !crypto::hmac_verify(&keys.hdr, hdr, &file.header_mac) {
            return Err(Error::Damaged);
        }
        let aad = format::index_aad(&file.uuid, file.generation)?;
        let pt = crypto::open(keys.index.expose(), &file.index_nonce, &aad, &file.index_ct)
            .map_err(|()| Error::Damaged)?;
        let index = Index::decode(pt.expose())?;
        let seen = keystore.tripwire(&index.tripwire_id, &file.uuid)?;
        let tripwire_gen = seen.unwrap_or(0).max(file.generation);
        let rolled_back = seen.is_some_and(|g| g > file.generation);
        Ok(Vault {
            file,
            index,
            keys,
            dirs: dirs.clone(),
            keystore,
            original: bytes,
            tripwire_gen,
            rolled_back,
        })
    }

    /// Decrypt one entry. Its version must equal the index version (FORMATS §1).
    pub fn read_entry(&self, handle: &str) -> Result<Secret> {
        let rec = self
            .index
            .get(handle)
            .ok_or_else(|| Error::NotFound(handle.to_owned()))?;
        let e = self
            .file
            .entries
            .iter()
            .find(|e| e.handle == handle)
            .ok_or(Error::Damaged)?;
        if e.version != rec.version {
            return Err(Error::Damaged);
        }
        let aad = format::entry_aad(&self.file.uuid, handle, e.version)?;
        crypto::open(self.keys.entry.expose(), &e.nonce, &aad, &e.ct).map_err(|()| Error::Damaged)
    }

    /// Encrypt `value` as the entry for `handle` at `version` (replacing any existing entry).
    pub fn put_entry(&mut self, handle: &str, version: u32, value: &Secret) -> Result<()> {
        let nonce: [u8; 24] = crypto::random()?;
        let aad = format::entry_aad(&self.file.uuid, handle, version)?;
        let ct = crypto::seal(self.keys.entry.expose(), &nonce, &aad, value.expose())?;
        self.file.entries.retain(|e| e.handle != handle);
        self.file.entries.push(RawEntry {
            handle: handle.to_owned(),
            version,
            nonce,
            ct,
        });
        Ok(())
    }

    pub fn remove_entry(&mut self, handle: &str) {
        self.file.entries.retain(|e| e.handle != handle);
    }

    /// Replace the passphrase slot (same DEK). Used by `passwd`, `recover`, `restore --new-machine`.
    pub fn set_passphrase(&mut self, pass: &Secret, pepper: &Secret) -> Result<()> {
        let slot =
            new_passphrase_slot(&self.file.uuid, pass, pepper, kdf_params(), &self.keys.dek)?;
        self.file
            .slots
            .retain(|s| s.kind != SlotKind::Passphrase as u8);
        self.file.slots.insert(0, slot);
        Ok(())
    }

    /// `rekey`: new DEK, every entry re-encrypted, new passphrase + recovery slots, previous values dropped.
    /// Unknown slot kinds are dropped too: they wrap the old DEK and would be useless.
    pub fn rekey(&mut self, pass: &Secret, rk: &Secret) -> Result<()> {
        let pepper = self.keystore.pepper_or_create()?;
        let handles: Vec<(String, u32)> = self
            .index
            .handles
            .iter()
            .map(|h| (h.handle.clone(), h.version))
            .collect();
        let mut values = Vec::with_capacity(handles.len());
        for (h, v) in &handles {
            values.push((h.clone(), *v, self.read_entry(h)?));
        }
        let dek = crypto::new_dek()?;
        let uuid = self.file.uuid;
        self.file.slots = vec![
            new_passphrase_slot(&uuid, pass, &pepper, kdf_params(), &dek)?,
            new_recovery_slot(&uuid, rk, &dek)?,
        ];
        self.keys = Keys::derive(&uuid, dek)?;
        self.file.entries.clear();
        for (h, v, val) in &values {
            self.put_entry(h, *v, val)?;
        }
        for r in &mut self.index.handles {
            r.previous_value = None;
            r.previous_version_until = None;
        }
        Ok(())
    }

    /// The broker's handshake proof for this vault (ADR 0004).
    pub fn broker_proof(&self, nc: &[u8], nb: &[u8]) -> Result<[u8; 32]> {
        let kb = crypto::subkey(&self.file.uuid, &self.keys.dek, crypto::label::BROKER)?;
        crypto::proof_broker(&kb, nc, nb)
    }

    /// `proof_c` for an authenticated request (ADR 0004): `HMAC(K_auth, enc("kg/v1/client")‖enc(nb)‖enc(nc)‖enc(H(req)))`.
    /// Both the CLI (after the passphrase) and the broker (to verify) compute it from the DEK.
    pub fn auth_proof(&self, nb: &[u8], nc: &[u8], request: &[u8]) -> Result<[u8; 32]> {
        let ka = crypto::subkey(&self.file.uuid, &self.keys.dek, crypto::label::AUTH)?;
        crypto::proof_client(&ka, nb, nc, request)
    }

    /// `K_audit` for the audit chain (SPEC §9).
    pub fn audit_key(&self) -> Result<crypto::Subkey> {
        crypto::subkey(&self.file.uuid, &self.keys.dek, crypto::label::AUDIT)
    }

    /// A copy of the DEK for reopening (the broker's reload). Lives in the locked arena when active.
    pub fn dek_copy(&self) -> Dek {
        Dek::from_bytes(*self.keys.dek.expose())
    }

    /// Generation of the file on disk right now (header only; no keys needed). The broker reloads when it differs.
    pub fn generation_on_disk(dirs: &Dirs) -> Result<u64> {
        let bytes = read_file(&Self::path(dirs))?.ok_or(Error::NoVault)?;
        Ok(format::parse(&bytes)?.0.generation)
    }

    pub fn keystore(&self) -> &Keystore {
        &self.keystore
    }

    /// The bytes that `.prev` should preserve on the next `Prev::Keep` commit (restore: the replaced live vault).
    pub fn set_original(&mut self, b: Vec<u8>) {
        self.original = b;
    }

    /// Serialize with a fresh generation, nonces and header MAC; write atomically; update `.prev` and the tripwire.
    pub fn commit(&mut self, prev: Prev) -> Result<()> {
        self.index.expire_previous(now());
        let live: std::collections::HashSet<&str> = self
            .index
            .handles
            .iter()
            .map(|h| h.handle.as_str())
            .collect();
        self.file
            .entries
            .retain(|e| live.contains(e.handle.as_str()));
        if self.file.entries.len() != self.index.handles.len() {
            return Err(Error::Internal(32));
        }
        self.file.entries.sort_by(|a, b| a.handle.cmp(&b.handle));
        let generation = self
            .tripwire_gen
            .max(self.file.generation)
            .checked_add(1)
            .ok_or(Error::Damaged)?;
        let pt = self.index.encode()?;
        let nonce: [u8; 24] = crypto::random()?;
        let aad = format::index_aad(&self.file.uuid, generation)?;
        let index_ct = crypto::seal(self.keys.index.expose(), &nonce, &aad, &pt)?;
        let mut file = self.file.clone();
        file.generation = generation;
        file.index_nonce = nonce;
        file.index_ct = index_ct;
        file.header_mac = crypto::hmac(
            &self.keys.hdr,
            &format::header_bytes(&file.uuid, generation, &file.slots)?,
        )?;
        let bytes = format::serialize(&file)?;

        let data = &self.dirs.data;
        if prev == Prev::Keep && !self.original.is_empty() {
            platform::atomic_replace(data, PREV_FILE, &self.original)?;
        }
        platform::atomic_replace(data, VAULT_FILE, &bytes)?;
        if prev == Prev::Drop {
            drop_old_copies(data);
        }
        self.keystore
            .set_tripwire(&self.index.tripwire_id, &file.uuid, generation)?;
        self.file = file;
        self.tripwire_gen = generation;
        self.original = bytes;
        self.rolled_back = false;
        Ok(())
    }
}

fn unwrap(file: &VaultFile, keystore: &Keystore, how: Unlock<'_>) -> Result<Dek> {
    match how {
        Unlock::Passphrase(pass) => {
            let slot = file
                .slots
                .iter()
                .find(|s| s.kind == SlotKind::Passphrase as u8)
                .ok_or(Error::Damaged)?;
            if slot.kdf_id != 1 {
                return Err(Error::Damaged);
            }
            let pepper = keystore.pepper()?.ok_or(Error::PepperMissing)?;
            let argon = crypto::argon2id(pass.expose(), &slot.salt, slot.kdf)?;
            let kek = crypto::kek_passphrase(&file.uuid, &argon, &pepper)?;
            crypto::unwrap_dek(&kek, &slot.nonce, &slot.aad(&file.uuid)?, &slot.wrapped)
                .map_err(|()| Error::WrongPassphrase)
        }
        Unlock::Recovery(rk) => {
            let slot = file
                .slots
                .iter()
                .find(|s| s.kind == SlotKind::Recovery as u8)
                .ok_or(Error::Damaged)?;
            let kek = crypto::kek_recovery(&file.uuid, rk)?;
            crypto::unwrap_dek(&kek, &slot.nonce, &slot.aad(&file.uuid)?, &slot.wrapped)
                .map_err(|()| Error::WrongRecoveryKey)
        }
    }
}

/// Best-effort removal of `.prev` and `.pre-v<N>` (overwriting is not reliable on SSD/APFS/CoW; SPEC §5.2).
fn drop_old_copies(data: &Path) {
    let _ = std::fs::remove_file(data.join(PREV_FILE));
    if let Ok(rd) = std::fs::read_dir(data) {
        for e in rd.flatten() {
            if e.file_name()
                .to_string_lossy()
                .starts_with("vault.kgt.pre-v")
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let _ = platform::os().sync_dir(data);
}

#[cfg(test)]
mod tests;
