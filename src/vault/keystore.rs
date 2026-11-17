//! Device pepper and rollback tripwire (SPEC §5.2).
//!
//! **Phase 1 backend: owner-only files in the state dir on every OS** — the documented SPEC §15 fallback ("store the
//! pepper in an owner-only file (weaker: equals a T2 copy); doctor says so"). The OS keystores (macOS Keychain with a
//! per-app ACL, DPAPI, Secret Service via `secret-tool`) need the Phase 0 keystore spike first; until then this is
//! weaker than the SPEC on macOS (no per-app ACL). The pepper file lives in the state dir, never next to the vault,
//! so a `backup` (a byte copy of the vault) never includes it.

use crate::crypto::{self, Secret};
use crate::error::{Error, Result};
use crate::platform::{self, Platform};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const PEPPER_FILE: &str = "device.key";
const PEPPER_LEN: usize = 32;
const TRIPWIRE_MAGIC: &[u8; 4] = b"KGTW";

pub struct Keystore {
    state: PathBuf,
}

impl Keystore {
    pub fn new(state: &Path) -> Result<Self> {
        platform::os().ensure_private_dir(state)?;
        Ok(Keystore {
            state: state.to_owned(),
        })
    }

    fn read_small(&self, name: &str, max: usize) -> Result<Option<Vec<u8>>> {
        let Some(f) = platform::os().open_private(&self.state.join(name))? else {
            return Ok(None);
        };
        let mut buf = Vec::with_capacity(max);
        f.take(u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1))
            .read_to_end(&mut buf)?;
        if buf.len() > max {
            return Err(Error::Damaged);
        }
        Ok(Some(buf))
    }

    pub fn pepper(&self) -> Result<Option<Secret>> {
        match self.read_small(PEPPER_FILE, PEPPER_LEN)? {
            Some(b) if b.len() == PEPPER_LEN => Ok(Some(Secret::new(b))),
            Some(_) => Err(Error::PepperMissing),
            None => Ok(None),
        }
    }

    /// Existing pepper, or a fresh random one (init / recover on a device that lost it).
    pub fn pepper_or_create(&self) -> Result<Secret> {
        if let Some(p) = self.pepper()? {
            return Ok(p);
        }
        let p = Secret::from_slice(&crypto::random::<PEPPER_LEN>()?);
        platform::atomic_replace(&self.state, PEPPER_FILE, p.expose())?;
        Ok(p)
    }

    fn tripwire_name(id: &[u8; 16]) -> String {
        format!("tripwire-{}", crate::crypto::hex(id))
    }

    /// Highest generation recorded for this vault on this device, if any.
    pub fn tripwire(&self, id: &[u8; 16], uuid: &[u8; 16]) -> Result<Option<u64>> {
        let Some(b) = self.read_small(&Self::tripwire_name(id), 28)? else {
            return Ok(None);
        };
        let (magic, rest) = b.split_at_checked(4).ok_or(Error::Damaged)?;
        let (u, g) = rest.split_at_checked(16).ok_or(Error::Damaged)?;
        if magic != TRIPWIRE_MAGIC || g.len() != 8 {
            return Err(Error::Damaged);
        }
        if u != uuid {
            return Ok(None);
        }
        Ok(Some(u64::from_le_bytes(
            g.try_into().map_err(|_| Error::Damaged)?,
        )))
    }

    pub fn set_tripwire(&self, id: &[u8; 16], uuid: &[u8; 16], generation: u64) -> Result<()> {
        let mut b = Vec::with_capacity(28);
        b.extend_from_slice(TRIPWIRE_MAGIC);
        b.extend_from_slice(uuid);
        b.extend_from_slice(&generation.to_le_bytes());
        platform::atomic_replace(&self.state, &Self::tripwire_name(id), &b)
    }

    pub fn clear_tripwire(&self, id: &[u8; 16]) -> Result<()> {
        match std::fs::remove_file(self.state.join(Self::tripwire_name(id))) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}
