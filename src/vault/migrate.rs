//! Forward-only format migrations (SPEC §5.2). Before a migration runs, the current file is saved as
//! `vault.kgt.pre-v<N>`. A newer format than this build supports is refused with "upgrade keygent".
//!
//! Format 1 is the first format, so the registry is empty; the runner is exercised by tests with a synthetic chain.
//! Migrations operate on the encrypted file layout only (header/slots/entries); index-level changes bump
//! `index_version` and are handled where the index is decrypted.

use super::format::{self, FORMAT_VERSION};
use crate::error::{Error, Result};
use crate::platform;
use std::path::Path;

/// One step: bytes of format `N` → bytes of format `N + 1`.
pub type Step = fn(&[u8]) -> Result<Vec<u8>>;

/// `MIGRATIONS[i]` upgrades format `i + 1` to `i + 2`. Empty in format 1.
const MIGRATIONS: &[Step] = &[];

pub fn migrate_if_needed(data: &Path, bytes: Vec<u8>) -> Result<Vec<u8>> {
    run(data, bytes, FORMAT_VERSION, MIGRATIONS)
}

/// Run `steps` from the file's version up to `target`, saving `vault.kgt.pre-v<N>` before the first step and writing
/// the migrated file atomically.
pub fn run(data: &Path, bytes: Vec<u8>, target: u16, steps: &[Step]) -> Result<Vec<u8>> {
    let from = format::peek_version(&bytes)?;
    if from > target {
        return Err(Error::FormatTooNew(from));
    }
    if from == target {
        return Ok(bytes);
    }
    if from == 0 {
        return Err(Error::Damaged);
    }
    platform::atomic_replace(data, &format!("vault.kgt.pre-v{from}"), &bytes)?;
    let mut cur = bytes;
    for v in from..target {
        let step = steps
            .get(usize::from(v.saturating_sub(1)))
            .ok_or(Error::FormatTooNew(from))?;
        cur = step(&cur)?;
        if format::peek_version(&cur)? != v.saturating_add(1) {
            return Err(Error::Internal(40));
        }
    }
    platform::atomic_replace(data, super::VAULT_FILE, &cur)?;
    Ok(cur)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "tests: a panic is the failure report"
    )]
    use super::*;

    fn bump(b: &[u8]) -> Result<Vec<u8>> {
        let mut v = b.to_vec();
        let n = u16::from_le_bytes([v[4], v[5]]) + 1;
        v[4..6].copy_from_slice(&n.to_le_bytes());
        v.extend_from_slice(b"+");
        Ok(v)
    }

    #[test]
    fn runs_chain_and_keeps_pre_copy() {
        let dir = std::env::temp_dir().join(format!("kg-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let v1 = b"KGNT\x01\x00rest".to_vec();
        let out = run(&dir, v1.clone(), 3, &[bump, bump]).unwrap();
        assert_eq!(format::peek_version(&out).unwrap(), 3);
        assert_eq!(&out[6..], b"rest++");
        assert_eq!(std::fs::read(dir.join("vault.kgt.pre-v1")).unwrap(), v1);
        assert_eq!(std::fs::read(dir.join("vault.kgt")).unwrap(), out);
        // newer than supported
        assert_eq!(
            run(&dir, out, 2, &[bump]).unwrap_err(),
            Error::FormatTooNew(3)
        );
        // missing step
        assert!(run(&dir, v1, 3, &[bump]).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
