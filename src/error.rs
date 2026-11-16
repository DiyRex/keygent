//! Error catalog (docs/ERRORS.md). Every keygent-originated failure maps to exactly one line, starting with `keygent:`,
//! at most 120 chars, and one exit code. Messages never carry secret values, passphrases or file contents.

use std::fmt;

/// Exit codes from SPEC §12 / ERRORS.md.
pub mod exit {
    pub const HUMAN: u8 = 1;
    pub const USAGE: u8 = 64;
    pub const SEALED: u8 = 78;
    pub const BROKER: u8 = 79;
}

/// Every failure keygent itself reports. Variants hold only non-secret data (handles, env names, limits, codes).
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Usage(&'static str),
    Sealed,
    NeedsAuth,
    TooWeak,
    PassphraseTooWeak,
    FormatTooNew(u16),
    DiskFull,
    NetworkFs,
    TooLarge(&'static str),
    WrongPassphrase,
    WrongRecoveryKey,
    NoVault,
    VaultExists,
    NotFound(String),
    Exists(String),
    Collision(String),
    InvalidHandle,
    InvalidEnvName,
    ReservedEnvName(String),
    ValueSize,
    Damaged,
    PepperMissing,
    RolledBack,
    UnsafePath(&'static str),
    NotRegularFile,
    Mismatch,
    Cancelled,
    NothingToUndo(String),
    UuidMismatch,
    Unsupported(&'static str),
    /// The process behind the endpoint is not the verified keygent broker (SPEC §5.4). Fail closed.
    BrokerUnverified,
    /// The redactor's 8 MiB pattern cap would be exceeded (SPEC §5.8).
    RedactorTooLarge,
    VersionMismatch,
    RateLimited,
    /// A protocol error code from the broker (ADR 0004), never request contents.
    Broker(u16),
    /// I/O or OS failure. The code is an `std::io::ErrorKind`-derived number, never a path or value.
    Io(i32),
    /// Internal invariant failure (crypto/RNG). The code identifies the site.
    Internal(u16),
}

impl Error {
    pub fn exit_code(&self) -> u8 {
        match self {
            Error::Usage(_) | Error::InvalidHandle | Error::InvalidEnvName => exit::USAGE,
            Error::Sealed => exit::SEALED,
            Error::TooLarge(_)
            | Error::Internal(_)
            | Error::BrokerUnverified
            | Error::VersionMismatch
            | Error::RateLimited
            | Error::Broker(_) => exit::BROKER,
            _ => exit::HUMAN,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(u) => write!(f, "keygent: usage: {u}"),
            Error::Sealed => f.write_str("keygent: vault sealed — ask the user to run 'keygent unseal'"),
            Error::NeedsAuth => f.write_str("keygent: this needs your passphrase — run it in your own terminal"),
            Error::TooWeak => {
                f.write_str("keygent: value too weak to redact safely — rotate it at the provider to a longer one")
            }
            Error::PassphraseTooWeak => {
                f.write_str("keygent: passphrase too weak — use 16+ chars and 5+ random words, or the generated one")
            }
            Error::FormatTooNew(n) => write!(f, "keygent: vault is format {n} — upgrade keygent"),
            Error::DiskFull => f.write_str("keygent: disk full — vault unchanged"),
            Error::NetworkFs => f.write_str(
                "keygent: vault on a network/sync folder is not supported — move it with 'keygent restore'",
            ),
            Error::TooLarge(n) => write!(f, "keygent: input too large (limit {n})"),
            Error::WrongPassphrase => f.write_str("keygent: wrong passphrase — nothing changed"),
            Error::WrongRecoveryKey => f.write_str("keygent: wrong recovery key — nothing changed"),
            Error::NoVault => f.write_str("keygent: no vault yet — run 'keygent init'"),
            Error::VaultExists => f.write_str("keygent: a vault already exists — use 'keygent passwd' or 'keygent restore'"),
            Error::NotFound(h) => write!(f, "keygent: {} not found — check the handle", short(h)),
            Error::Exists(h) => write!(f, "keygent: {} already exists — use 'keygent rotate' to change it", short(h)),
            Error::Collision(h) => write!(f, "keygent: name clashes with {} — pick another handle", short(h)),
            Error::InvalidHandle => f.write_str("keygent: invalid handle — use lower-case a-z 0-9 . _ - and up to 4 '/' parts"),
            Error::InvalidEnvName => f.write_str("keygent: invalid env name — use A-Z 0-9 _ (max 64)"),
            Error::ReservedEnvName(n) => write!(f, "keygent: env name {} is reserved — pick another", short(n)),
            Error::ValueSize => f.write_str("keygent: value must be 12 bytes to 64 KiB"),
            Error::Damaged => f.write_str("keygent: vault damaged — run 'keygent verify'"),
            Error::PepperMissing => {
                f.write_str("keygent: this device's key is missing — run 'keygent recover' with your recovery key")
            }
            Error::RolledBack => f.write_str("keygent: vault is older than expected (rolled back?) — nothing changed"),
            Error::UnsafePath(what) => write!(f, "keygent: unsafe {what} (owner, mode or symlink) — run 'keygent doctor'"),
            Error::NotRegularFile => f.write_str("keygent: not a regular file owned by you"),
            Error::Mismatch => f.write_str("keygent: confirmation didn't match — nothing changed"),
            Error::Cancelled => f.write_str("keygent: cancelled — nothing changed"),
            Error::NothingToUndo(h) => write!(f, "keygent: nothing to undo for {} (only within 24 h of a rotate)", short(h)),
            Error::UuidMismatch => f.write_str("keygent: backup belongs to a different vault — use 'restore --new-machine'"),
            Error::Unsupported(what) => write!(f, "keygent: {what} is not supported on this platform yet"),
            Error::BrokerUnverified => {
                f.write_str("keygent: broker could not be verified — run 'keygent doctor'")
            }
            Error::VersionMismatch => {
                f.write_str("keygent: updated — run 'keygent seal' then 'keygent unseal'")
            }
            Error::RateLimited => f.write_str("keygent: too many requests — retry in a few seconds"),
            Error::RedactorTooLarge => {
                f.write_str("keygent: too many or too large secrets to redact safely — remove some or split vaults")
            }
            Error::Broker(code) => write!(f, "keygent: broker error {code} — run 'keygent doctor'"),
            Error::Io(code) => write!(f, "keygent: file error {code} — run 'keygent doctor'"),
            Error::Internal(code) => write!(f, "keygent: internal error {code} — run 'keygent doctor'"),
        }
    }
}

/// Keeps templated lines within 120 chars: handles and env names are cut to 48 chars.
fn short(s: &str) -> String {
    if s.chars().count() <= 48 {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(47).collect();
    t.push('…');
    t
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::StorageFull {
            return Error::DiskFull;
        }
        Error::Io(e.raw_os_error().unwrap_or(-1))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden: every message starts with `keygent:` and fits in 120 chars (ERRORS.md).
    #[test]
    fn messages_are_single_short_lines() {
        let long = "a".repeat(255);
        let all = [
            Error::Usage("keygent add <handle>"),
            Error::Sealed,
            Error::NeedsAuth,
            Error::TooWeak,
            Error::PassphraseTooWeak,
            Error::FormatTooNew(2),
            Error::DiskFull,
            Error::NetworkFs,
            Error::TooLarge("64 KiB"),
            Error::WrongPassphrase,
            Error::WrongRecoveryKey,
            Error::NoVault,
            Error::VaultExists,
            Error::NotFound(long.clone()),
            Error::Exists(long.clone()),
            Error::Collision(long.clone()),
            Error::InvalidHandle,
            Error::InvalidEnvName,
            Error::ReservedEnvName(long.clone()),
            Error::ValueSize,
            Error::Damaged,
            Error::PepperMissing,
            Error::RolledBack,
            Error::UnsafePath("data dir"),
            Error::NotRegularFile,
            Error::Mismatch,
            Error::Cancelled,
            Error::NothingToUndo(long.clone()),
            Error::UuidMismatch,
            Error::Unsupported("clipboard"),
            Error::BrokerUnverified,
            Error::RedactorTooLarge,
            Error::VersionMismatch,
            Error::RateLimited,
            Error::Broker(10),
            Error::Io(28),
            Error::Internal(1),
        ];
        for e in all {
            let s = e.to_string();
            assert!(s.starts_with("keygent: "), "{s}");
            assert!(s.chars().count() <= 120, "{s}");
            assert!(!s.contains('\n'));
        }
    }

    #[test]
    fn exit_codes() {
        assert_eq!(Error::Sealed.exit_code(), 78);
        assert_eq!(Error::Usage("x").exit_code(), 64);
        assert_eq!(Error::TooLarge("x").exit_code(), 79);
        assert_eq!(Error::WrongPassphrase.exit_code(), 1);
        assert_eq!(Error::DiskFull.exit_code(), 1);
    }
}
