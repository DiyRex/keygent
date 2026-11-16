//! Wire and storage encodings shared by the vault index and (Phase 2) the broker protocol.
//! No plaintext types live here (SPEC §4.2): this module only moves bytes.

pub mod frame;
pub mod msg;
pub mod tags;
pub mod tlv;
