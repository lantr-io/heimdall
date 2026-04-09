//! Tiny helpers for the granular `eprintln!` traces in `dkg.rs`,
//! `signing.rs`, and `machine.rs`.
//!
//! The state machine logs to stderr in a deliberate, line-based format
//! so a developer running `heimdall demo` in three terminals can follow
//! the DKG / signing protocol step by step.

use frost_secp256k1_tr::Identifier;

/// Render an `Identifier` as the small integer pool index that the
/// demo fixtures use (1, 2, 3, …). Identifiers serialize as 32-byte
/// big-endian scalars; in the demo only the last two bytes are used.
pub fn id_short(id: Identifier) -> u16 {
    let bytes = id.serialize();
    let n = bytes.len();
    u16::from_be_bytes([bytes[n - 2], bytes[n - 1]])
}

/// Format the first `take` bytes of `data` as hex with an ellipsis if
/// there's more. Used for showing wire payloads compactly in trace
/// output.
pub fn short_hex(data: &[u8], take: usize) -> String {
    if data.len() <= take {
        hex::encode(data)
    } else {
        format!("{}…({} more)", hex::encode(&data[..take]), data.len() - take)
    }
}

/// Standard log line prefix used by every state-machine trace print.
/// Includes this SPO's pool index and the epoch number so concurrent
/// SPOs are distinguishable in interleaved output.
#[macro_export]
macro_rules! epoch_log {
    ($me:expr, $epoch:expr, $($arg:tt)*) => {{
        eprintln!(
            "[spo={} epoch={}] {}",
            $crate::epoch::log::id_short($me),
            $epoch,
            format_args!($($arg)*)
        );
    }};
}
