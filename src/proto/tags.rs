//! TLV tag registry (FORMATS §2). Tags are globally unique per struct range and **never reused**.
//! Golden byte vectors: `tests/golden/tlv/`.

/// Vault index, top level (index_version 1).
pub mod index {
    pub const INDEX_VERSION: u16 = 0x0101;
    pub const HANDLE: u16 = 0x0102;
    pub const TRUSTED_MANIFEST: u16 = 0x0103;
    pub const PASSKEY: u16 = 0x0104;
    pub const SHELL_PATHS: u16 = 0x0105;
    pub const UI_BINARY_SHA256: u16 = 0x0106;
    pub const SECURITY_SETTINGS: u16 = 0x0107;
    pub const AUDIT_ANCHOR: u16 = 0x0108;
    pub const TRIPWIRE_ID: u16 = 0x0109;
}

/// `handles[]` entry.
pub mod handle {
    pub const HANDLE: u16 = 0x0201;
    pub const ENV_NAME: u16 = 0x0202;
    pub const DESCRIPTION: u16 = 0x0203;
    pub const BINDING: u16 = 0x0204;
    pub const MODE: u16 = 0x0205;
    pub const ALLOW_RULE: u16 = 0x0206;
    pub const HOST: u16 = 0x0207;
    pub const CREATED_AT: u16 = 0x0208;
    pub const ROTATED_AT: u16 = 0x0209;
    pub const VERSION: u16 = 0x020a;
    pub const PREVIOUS_VERSION_UNTIL: u16 = 0x020b;
    pub const EXPOSED: u16 = 0x020c;
    pub const ORIGIN: u16 = 0x020d;
    pub const ARGV: u16 = 0x020e;
    pub const CONFIG_SEEN: u16 = 0x020f;
    /// The value replaced by the last `rotate`, kept for 24 h (SPEC §5.2 "previous values for 24 h").
    pub const PREVIOUS_VALUE: u16 = 0x0210;
}

pub mod allow_rule {
    pub const EXE: u16 = 0x0301;
    pub const SHA256: u16 = 0x0302;
    pub const ARG: u16 = 0x0303;
    pub const FLAG: u16 = 0x0304;
    pub const HOME: u16 = 0x0305;
}

pub mod flag {
    pub const NAME: u16 = 0x0401;
    pub const TAKES_VALUE: u16 = 0x0402;
}

pub mod trusted_manifest {
    pub const CANONICAL_PATH: u16 = 0x0501;
    pub const SHA256: u16 = 0x0502;
    pub const TRUSTED_AT: u16 = 0x0503;
}

pub mod passkey {
    pub const CREDENTIAL_ID: u16 = 0x0601;
    pub const COSE_PUBKEY: u16 = 0x0602;
    pub const SIGN_COUNT: u16 = 0x0603;
    pub const LABEL: u16 = 0x0604;
    pub const CREATED_AT: u16 = 0x0605;
}

pub mod shell_paths {
    pub const POSIX: u16 = 0x0701;
    pub const GIT_BASH: u16 = 0x0702;
    pub const PWSH: u16 = 0x0703;
}

pub mod security {
    pub const TTL_MAX: u16 = 0x0801;
    pub const IDLE: u16 = 0x0802;
    pub const RUN_MAX_MINUTES: u16 = 0x0803;
    pub const REMEMBER_ENABLED: u16 = 0x0804;
    pub const DEFAULT_MODE: u16 = 0x0805;
}

pub mod audit_anchor {
    pub const SEQ: u16 = 0x0901;
    pub const MAC: u16 = 0x0902;
}

pub mod config_seen {
    pub const TOOL: u16 = 0x0a01;
    pub const PATH: u16 = 0x0a02;
    pub const SHA256: u16 = 0x0a03;
    pub const APPROVED_AT: u16 = 0x0a04;
}

/// Broker protocol payload tags (ADR 0004, big-endian TLV). Range `0x10xx`–`0x1fxx`.
pub mod proto {
    pub const BUILD_ID: u16 = 0x1001;
    pub const NONCE: u16 = 0x1002;
    pub const CLASS: u16 = 0x1003;
    pub const PROOF: u16 = 0x1004;
    pub const CODE: u16 = 0x1005;
    pub const MESSAGE: u16 = 0x1006;
    pub const PID: u16 = 0x1010;
    pub const TTL_LEFT: u16 = 0x1011;
    pub const IDLE_LEFT: u16 = 0x1012;
    pub const HANDLE_COUNT: u16 = 0x1013;
    pub const NO_DUMPS: u16 = 0x1014;
    pub const MLOCKALL: u16 = 0x1015;
    pub const ENTRY: u16 = 0x1020;
    pub const E_HANDLE: u16 = 0x1021;
    pub const E_ENV: u16 = 0x1022;
    pub const E_MODE: u16 = 0x1023;
    pub const E_BINDING: u16 = 0x1024;
    pub const E_EXPOSED: u16 = 0x1025;
    pub const E_DESCRIPTION: u16 = 0x1026;
    pub const DATA: u16 = 0x1030;
    pub const HITS: u16 = 0x1031;
    pub const CMD: u16 = 0x1040;
    pub const CWD: u16 = 0x1041;
    pub const MAX_RUNTIME: u16 = 0x1042;
    pub const GRANT_ID: u16 = 0x1043;
    pub const GRANT_KEY: u16 = 0x1044;
    pub const GRANT_STATE: u16 = 0x1045;
    pub const RENDERED: u16 = 0x1046;
    pub const REMEMBER: u16 = 0x1047;
    pub const ALL: u16 = 0x1048;
    pub const EXIT_CODE: u16 = 0x1049;
    pub const SIGNAL: u16 = 0x104a;
    pub const GRANT: u16 = 0x104b;
    pub const UNBOUND: u16 = 0x104c;
}

/// Unseal handoff over the inherited pipe (CLI → `keygent broker`), little-endian TLV. Range `0x20xx`.
pub mod handoff {
    pub const DEK: u16 = 0x2001;
    pub const TTL: u16 = 0x2002;
    pub const IDLE: u16 = 0x2003;
    pub const LOG_LEVEL: u16 = 0x2004;
    pub const PATH: u16 = 0x2005;
}
