//! The federation setup key — `federation_setup_Y` — and the ceremony that
//! produces it (WI-087).
//!
//! ## One value, two names
//!
//! What this module produces and what the rest of heimdall reads are the same 32
//! bytes at different moments in a bridge's life, and the names keep them apart:
//!
//! - **`federation_setup_Y`** — here. The output of the ceremony, held as shares
//!   by the members, existing before the bridge does and readable from nowhere
//!   but their own machines.
//! - **`y_federation`** — everywhere else ([`crate::cardano::federation`]). The
//!   same key once genesis publishes it at **Config #11**, after which every node
//!   and every depositor reads it from the chain rather than being told it.
//!
//! The distinction is not pedantry: the setup name marks exactly the window in
//! which a local value is authoritative. Outside it, a node taking this key from
//! its own disk instead of the Config is the bug — see
//! [`crate::cardano::federation::resolve`], where published always wins and a
//! local copy is only ever a cross-check.
//!
//! It is the key in the CSV recovery leaf of both Taproot trees, the
//! treasury's and every peg-in deposit's. It is how the treasury moves when the
//! FROST group is dark, once `federation_csv_blocks` have passed. Until WI-087 it
//! was a single 32-byte seed (`bitcoin.y_fed_seed_hex`) held by one party — so
//! the mechanism that exists *because* the signing group might be unavailable was
//! itself a single point of failure, and whoever held the seed could sweep the
//! entire treasury alone after the delay. This module replaces that seed with a
//! `t`-of-`n` FROST key, which removes both properties at once.
//!
//! ## Why it cannot reuse the epoch DKG
//!
//! The epoch ceremony ([`crate::epoch::dkg`]) reads its candidate set from the
//! on-chain registry, filters it by the ban list, weights it by stake and anchors
//! its schedule to the epoch boundary. Every one of those inputs is rooted in the
//! Config NFT — and this key is an *input to genesis*: it becomes Config #11, and
//! the treasury ADDRESS the genesis anchor is funded at is derived from it. The
//! key must therefore exist before the bridge does. **There is no chain to read.**
//!
//! So the roster is typed in ([`crate::config::FederationConfig`]): every member's
//! `(bifrost_url, bifrost_id_pk)`, and nothing else. What IS reused is everything
//! below the roster — the authenticated HTTP transport
//! ([`crate::http::peer_network`]), which addresses peers by URL and verifies them
//! by identity key, and the per-participant FROST rounds
//! ([`crate::frost::participant`]). Only the source of the participant list, and
//! the liveness rule over it, are new.
//!
//! ## Liveness is n-of-n PRESENCE, not a window
//!
//! The ceremony runs until *every* listed participant is online. There is no epoch
//! boundary to anchor a deadline to and no stake to weight a surviving subset by,
//! so the epoch machine's window / health-gate / threshold-subset model does not
//! apply: a federation that is forming has no deadline, and a member missing from
//! the ceremony is a member who can never sign. Hence no reduced-set rerun here —
//! [`ceremony::run_dkg`] waits, reports who it is waiting for, and only stops if
//! the operator sets an explicit deadline.
//!
//! **Presence is not the threshold.** All `n` must attend the ceremony; how many
//! it then takes to SIGN is `federation.min_signers`, a separate and deliberate
//! choice — see [`roster::FederationRoster::min_signers`].
//!
//! ## What is namespaced apart, and why
//!
//! Ceremony payloads travel the same wire and the same routes as the epoch DKG's,
//! under the reserved namespace label
//! [`crate::http::canonical::THRESHOLD_FEDERATION`]. That label is inside the
//! signed canonical bytes, not merely in the URL, so a Round-1 package from an
//! epoch ceremony can never be replayed into this one (or the reverse) however the
//! two are scheduled.

pub mod ceremony;
pub mod persist;
pub mod roster;
pub mod spend;

pub use ceremony::{CeremonyError, CeremonyLimits};
pub use persist::FederationKeyState;
pub use roster::{FederationMember, FederationRoster, RosterError};
