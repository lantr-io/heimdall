//! The two files an air-gapped registration or exit travels on.
//!
//! `register-spo` / `deregister-spo` emit a [`SigningRequest`] on the node;
//! `sign-with-pool-key` turns it into a [`SignedResponse`] beside the pool cold
//! key; the node reads that back and finishes the transaction. See
//! `docs/superpowers/specs/2026-09-17-airgapped-pool-key-signing-design.md`.
//!
//! Errors are `String`: every caller is a `run_*` in `main.rs` that prints them,
//! and the messages are the point — each one names both sides of the mismatch it
//! found, so a wrong file fails legibly instead of as a bad signature.

use pallas_crypto::key::ed25519;
use serde::{Deserialize, Serialize};

use crate::cardano::deregister_spo::{RevocationSignature, revocation_message, verify_revocation};
use crate::cardano::register_spo::{pool_id_from_cold_vkey, registration_message};
use crate::cardano::tx_common::NonceOutpoint;

/// The file format version. Bumped when a field changes meaning, not when one
/// is added.
///
/// `2` is the rev-5.6 nonce: both signed messages gained a trailing outpoint
/// ([REG-10], [DRG-6]), so a `v: 1` file's signature covers a preimage the
/// chain no longer builds. Such a file is refused by name rather than accepted
/// and left to fail as an invalid signature after a fee is spent — there is
/// nothing it could still authorize.
pub const VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Register,
    Deregister,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Action::Register => "register",
            Action::Deregister => "deregister",
        })
    }
}

/// What the node asks the cold key to authorize.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRequest {
    pub v: u32,
    pub heimdall: String,
    pub action: Action,
    /// Display only: which bridge, so the offline machine can name it.
    pub network: String,
    pub registry_policy: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bifrost_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub bifrost_id_pk: Option<String>,
    /// Present when the node can derive it: always for an exit (the pool is in
    /// the registry), only with `cardano.cold_vkey_path` for a registration.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pool_id: Option<String>,
    /// spec [REG-10], [DRG-6]: the UTxO this signature will be bound to, as
    /// `<txid hex>#<index>`. Chosen by the node among the wallet's own UTxOs and
    /// reserved until the transaction lands, so nothing else spends it meanwhile.
    ///
    /// Not optional in practice — every `v: 2` request carries it, and
    /// [`message_of`] fails without it rather than signing a shorter preimage
    /// that would look like a valid rev-5.5 message. It is `Option` only so the
    /// field's absence in a hand-written file is reported as the missing nonce
    /// rather than as malformed JSON.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nonce_outpoint: Option<String>,
    /// The exact preimage the cold key signs, when `pool_id` is known. For an
    /// operator who would rather sign with their own Ed25519 tool and pass the
    /// result to `--cold-sig`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message: Option<String>,
}

/// What comes back from the machine that holds the cold key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedResponse {
    pub v: u32,
    pub heimdall: String,
    pub action: Action,
    /// The request verbatim, so the node can report *what was signed* rather
    /// than only that the signature does not verify.
    pub request: SigningRequest,
    pub pool_id: String,
    pub cold_vkey: String,
    pub cold_sig: String,
}

impl SigningRequest {
    /// A registration request. `pool_id` is `None` when the node has no cold
    /// verification key: a registering pool is in no registry, so nothing on
    /// chain can tell it its own id.
    #[must_use]
    pub fn register(
        network: &str,
        registry_policy: &str,
        bifrost_url: &str,
        bifrost_id_pk: &[u8; 32],
        pool_id: Option<[u8; 28]>,
        nonce: NonceOutpoint,
    ) -> Self {
        let message = pool_id
            .map(|id| registration_message(&id, bifrost_id_pk, bifrost_url.as_bytes(), &nonce))
            .map(hex::encode);
        Self {
            v: VERSION,
            heimdall: version(),
            action: Action::Register,
            network: network.to_string(),
            registry_policy: registry_policy.to_string(),
            bifrost_url: Some(bifrost_url.to_string()),
            bifrost_id_pk: Some(hex::encode(bifrost_id_pk)),
            pool_id: pool_id.map(hex::encode),
            nonce_outpoint: Some(nonce.to_string()),
            message,
        }
    }

    /// An exit request. The pool is already in the registry, so its id is always
    /// known here and the message is always complete.
    #[must_use]
    pub fn deregister(
        network: &str,
        registry_policy: &str,
        pool_id: &[u8; 28],
        nonce: NonceOutpoint,
    ) -> Self {
        Self {
            v: VERSION,
            heimdall: version(),
            action: Action::Deregister,
            network: network.to_string(),
            registry_policy: registry_policy.to_string(),
            bifrost_url: None,
            bifrost_id_pk: None,
            pool_id: Some(hex::encode(pool_id)),
            nonce_outpoint: Some(nonce.to_string()),
            message: Some(hex::encode(revocation_message(pool_id, &nonce))),
        }
    }

    /// The nonce outpoint this request is bound to.
    pub fn nonce(&self) -> Result<NonceOutpoint, String> {
        let raw = self.nonce_outpoint.as_deref().ok_or(
            "this request carries no nonce_outpoint. Every registration and exit signature is \
             bound to one UTxO since rev 5.6 ([REG-10], [DRG-6]); a request without it names no \
             transaction and cannot be signed",
        )?;
        NonceOutpoint::parse(raw)
    }
}

impl SignedResponse {
    /// Check a response against the request this node would emit *now*, and
    /// return the cold half for the transaction.
    ///
    /// `local_cold_vkey` is `cardano.cold_vkey_path` when it is set: a node told
    /// which pool it is must not accept a file that says a different one.
    pub fn check(
        &self,
        now: &SigningRequest,
        local_cold_vkey: Option<[u8; 32]>,
    ) -> Result<([u8; 32], [u8; 64]), String> {
        check_version(self.v, &self.heimdall)?;
        if self.action != now.action {
            return Err(format!(
                "this file authorizes a {} and you are running a {}",
                self.action, now.action
            ));
        }
        differ("bifrost_url", &self.request.bifrost_url, &now.bifrost_url)?;
        differ(
            "bifrost_id_pk",
            &self.request.bifrost_id_pk,
            &now.bifrost_id_pk,
        )?;
        // spec [REG-10], [DRG-6]. The one field whose drift is not the
        // operator's doing: the node picks the nonce, so a mismatch here means
        // the reservation was lost and a DIFFERENT UTxO would be spent — which
        // the chain would report only as an invalid signature.
        differ(
            "nonce_outpoint",
            &self.request.nonce_outpoint,
            &now.nonce_outpoint,
        )?;

        let cold_vkey: [u8; 32] = parse_hex(&self.cold_vkey, "cold_vkey")?;
        let cold_sig: [u8; 64] = parse_hex(&self.cold_sig, "cold_sig")?;
        let pool_id = pool_id_from_cold_vkey(&cold_vkey);
        if parse_hex::<28>(&self.pool_id, "pool_id")? != pool_id {
            return Err(
                "this file's pool_id is not the hash of its cold_vkey — it was edited \
                 or truncated in transit"
                    .to_string(),
            );
        }
        // The pool the NODE is acting for. An exit finds it in the registry by
        // the bifrost key, so it is known there even with no cold key here —
        // and a file for another pool would otherwise verify against its own
        // cold_vkey and build that pool's transaction from this node's entry.
        if let Some(expected) = &now.pool_id
            && parse_hex::<28>(expected, "pool_id")? != pool_id
        {
            return Err(format!(
                "this file is for a different pool than the one this node is acting for.\n  \
                 file:  {}\n  node:  {expected}",
                hex::encode(pool_id),
            ));
        }
        if let Some(local) = local_cold_vkey
            && local != cold_vkey
        {
            return Err(format!(
                "this file was signed by a cold key that is not the one \
                 cardano.cold_vkey_path names.\n  file:   {}\n  config: {}",
                hex::encode(cold_vkey),
                hex::encode(local),
            ));
        }

        // The cold half, verified here rather than after a chain read: a file
        // edited in transit should fail on the operator's own desk.
        verify(now, &cold_vkey, &cold_sig, &message_of(now, &pool_id)?)?;
        Ok((cold_vkey, cold_sig))
    }
}

fn check_version(v: u32, written_by: &str) -> Result<(), String> {
    if v == VERSION {
        return Ok(());
    }
    // A v1 file is refused by NAME, not silently retried: its signature covers
    // the rev-5.5 preimage, which ends at the URL (registration) or the pool id
    // (exit), and the chain now rebuilds a message with a 36-byte nonce after
    // that. There is no transaction the old signature still authorizes, so
    // accepting the file would only move the failure to after a fee is spent.
    if v == 1 {
        return Err(format!(
            "sign again: the message format changed. This file is format version 1, written by \
             heimdall {written_by}; this one is {} and speaks version {VERSION}. Since spec rev \
             5.6 both signed messages end with the outpoint of a UTxO the transaction spends \
             ([REG-10], [DRG-6]), which makes the signature single-use — so a version 1 signature \
             can no longer verify on chain against any transaction. Re-run the request command and \
             take the new file to the cold key.",
            version(),
        ));
    }
    Err(format!(
        "this file is format version {v} and this heimdall speaks version {VERSION}. \
         It was written by heimdall {written_by}; this one is {}",
        version(),
    ))
}

/// Report a field that moved between signing and submitting, naming both sides.
/// The whole reason the response carries the request: without it this is an
/// invalid signature and nothing more.
fn differ(what: &str, signed: &Option<String>, now: &Option<String>) -> Result<(), String> {
    if signed == now {
        return Ok(());
    }
    Err(format!(
        "{what} changed after this was signed, so the cold signature no longer covers it.\n  \
         signed:  {}\n  now:     {}",
        signed.as_deref().unwrap_or("(absent)"),
        now.as_deref().unwrap_or("(absent)"),
    ))
}

fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Sign a request with the pool cold key.
///
/// Refuses a request this key cannot be about: a `pool_id` the key does not
/// produce means the operator is at the wrong safe, or carried the wrong file.
/// Self-verifies before returning, the same check `spos_registry.ak` performs.
pub fn sign(req: &SigningRequest, cold: &ed25519::SecretKey) -> Result<SignedResponse, String> {
    check_version(req.v, &req.heimdall)?;
    let cold_vkey: [u8; 32] = cold.public_key().into();
    let pool_id = pool_id_from_cold_vkey(&cold_vkey);
    // The wrong-safe check, and the only one this machine can make on its own:
    // the request named a pool, and this key is not it.
    if let Some(named) = &req.pool_id {
        let named: [u8; 28] = parse_hex(named, "pool_id")?;
        if named != pool_id {
            return Err(format!(
                "this request is for a pool this cold key does not produce.\n  \
                 request:  {}\n  cold key: {}",
                hex::encode(named),
                hex::encode(pool_id),
            ));
        }
    }
    let message = message_of(req, &pool_id)?;

    let cold_sig: [u8; 64] = cold
        .sign(&message)
        .as_ref()
        .try_into()
        .expect("ed25519 signature is 64 bytes");

    // The self-check the air-gapped signer has always done: if the message built
    // here and the one the validator builds ever diverge, that must fail beside
    // the cold key, not after a fee is spent on the other machine.
    verify(req, &cold_vkey, &cold_sig, &message)?;

    Ok(SignedResponse {
        v: VERSION,
        heimdall: version(),
        action: req.action,
        request: req.clone(),
        pool_id: hex::encode(pool_id),
        cold_vkey: hex::encode(cold_vkey),
        cold_sig: hex::encode(cold_sig),
    })
}

/// The exact bytes the cold key signs for this request.
fn message_of(req: &SigningRequest, pool_id: &[u8; 28]) -> Result<Vec<u8>, String> {
    let nonce = req.nonce()?;
    match req.action {
        Action::Deregister => Ok(revocation_message(pool_id, &nonce)),
        Action::Register => {
            let url = req
                .bifrost_url
                .as_deref()
                .ok_or("a register request with no bifrost_url")?;
            let pk: [u8; 32] = parse_hex(
                req.bifrost_id_pk
                    .as_deref()
                    .ok_or("a register request with no bifrost_id_pk")?,
                "bifrost_id_pk",
            )?;
            Ok(registration_message(pool_id, &pk, url.as_bytes(), &nonce))
        }
    }
}

fn verify(
    req: &SigningRequest,
    cold_vkey: &[u8; 32],
    cold_sig: &[u8; 64],
    message: &[u8],
) -> Result<(), String> {
    let ok = match req.action {
        Action::Deregister => verify_revocation(&RevocationSignature {
            cold_vkey: *cold_vkey,
            cold_sig: *cold_sig,
            nonce: req.nonce()?,
        })
        .is_ok(),
        // The registration half the validator checks against the cold key. The
        // bifrost half is signed on the node, which is where that key lives.
        Action::Register => ed25519::PublicKey::from(*cold_vkey)
            .verify(message, &ed25519::Signature::from(*cold_sig)),
    };
    if ok {
        Ok(())
    } else {
        Err(
            "self-check failed, refusing to sign: the signature this key just made does not \
             verify under it"
                .to_string(),
        )
    }
}

fn parse_hex<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let raw = hex::decode(s.trim()).map_err(|e| format!("{what}: not hex: {e}"))?;
    let len = raw.len();
    raw.try_into()
        .map_err(|_| format!("{what}: expected {N} bytes, got {len}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cold_key(seed: u8) -> ed25519::SecretKey {
        ed25519::SecretKey::from([seed; 32])
    }

    /// The nonce every fixture request is bound to ([REG-10], [DRG-6]).
    fn nonce() -> NonceOutpoint {
        NonceOutpoint::new([0x7a; 32], 3)
    }

    fn other_nonce() -> NonceOutpoint {
        NonceOutpoint::new([0x5c; 32], 1)
    }

    #[test]
    fn signing_refuses_a_request_for_a_pool_this_key_is_not() {
        let req = SigningRequest::deregister("preprod", "7d21", &[0xab; 28], nonce());

        let err = sign(&req, &cold_key(7)).expect_err("must refuse");

        assert!(err.contains(&hex::encode([0xab; 28])), "{err}");
        assert!(err.contains("cold key"), "{err}");
    }

    #[test]
    fn signing_refuses_a_request_from_a_newer_format() {
        let mut req = SigningRequest::deregister("preprod", "7d21", &[0xab; 28], nonce());
        req.v = VERSION + 1;

        let err = sign(&req, &cold_key(7)).expect_err("must refuse");

        assert!(err.contains(&format!("version {}", VERSION + 1)), "{err}");
    }

    #[test]
    fn an_exit_response_is_refused_by_register_spo() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let signed = sign(
            &SigningRequest::deregister("preprod", "7d21", &pool_id, nonce()),
            &cold,
        )
        .expect("signing");

        let now = SigningRequest::register(
            "preprod",
            "7d21",
            "http://spo:8080",
            &[9u8; 32],
            None,
            nonce(),
        );
        let err = signed.check(&now, None).expect_err("must refuse");

        assert!(err.contains("deregister"), "{err}");
        assert!(err.contains("register"), "{err}");
    }

    #[test]
    fn a_response_for_another_pool_is_refused_when_the_request_names_one() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let signed = sign(
            &SigningRequest::deregister("preprod", "7d21", &pool_id, nonce()),
            &cold,
        )
        .expect("signing");

        // What the node looked up for ITSELF in the registry, which is not the
        // pool this file speaks for.
        let now = SigningRequest::deregister("preprod", "7d21", &[0xab; 28], nonce());
        let err = signed.check(&now, None).expect_err("must refuse");

        assert!(err.contains(&hex::encode([0xab; 28])), "{err}");
        assert!(err.contains(&hex::encode(pool_id)), "{err}");
    }

    #[test]
    fn a_response_for_another_pool_is_refused_by_a_node_that_knows_its_own() {
        let cold = cold_key(7);
        let req = SigningRequest::register(
            "preprod",
            "7d21",
            "http://spo:8080",
            &[9u8; 32],
            None,
            nonce(),
        );
        let signed = sign(&req, &cold).expect("signing");

        let err = signed
            .check(&req, Some([0x11; 32]))
            .expect_err("must refuse");

        assert!(err.contains("cold_vkey"), "{err}");
    }

    #[test]
    fn a_tampered_signature_is_refused_before_any_chain_read() {
        let cold = cold_key(7);
        let req = SigningRequest::register(
            "preprod",
            "7d21",
            "http://spo:8080",
            &[9u8; 32],
            None,
            nonce(),
        );
        let mut signed = sign(&req, &cold).expect("signing");
        signed.cold_sig.replace_range(0..2, "ff");

        let err = signed.check(&req, None).expect_err("must refuse");

        assert!(err.contains("does not verify"), "{err}");
    }

    #[test]
    fn a_response_survives_the_trip_as_json() {
        let cold = cold_key(7);
        let req = SigningRequest::register(
            "preprod",
            "7d21",
            "http://spo:8080",
            &[9u8; 32],
            None,
            nonce(),
        );
        let signed = sign(&req, &cold).expect("signing");

        let text = serde_json::to_string_pretty(&signed).expect("encode");
        let back: SignedResponse = serde_json::from_str(&text).expect("decode");

        assert_eq!(back, signed);
        assert!(text.contains("\"action\": \"register\""), "{text}");
    }

    #[test]
    fn an_exit_request_always_carries_the_message_to_sign() {
        let req = SigningRequest::deregister("preprod", "7d21", &[0xab; 28], nonce());

        assert_eq!(
            req.message.as_deref(),
            Some(hex::encode(revocation_message(&[0xab; 28], &nonce())).as_str())
        );
    }

    #[test]
    fn a_checked_register_response_carries_the_signature_the_node_would_have_made() {
        let cold = cold_key(3);
        let pk = [4u8; 32];
        let req =
            SigningRequest::register("preprod", "7d21", "http://spo:8080", &pk, None, nonce());

        let signed = sign(&req, &cold).expect("signing");
        let (cold_vkey, cold_sig) = signed.check(&req, None).expect("check");

        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let expected = cold.sign(registration_message(
            &pool_id,
            &pk,
            b"http://spo:8080",
            &nonce(),
        ));
        assert_eq!(cold_vkey, <[u8; 32]>::from(cold.public_key()));
        assert_eq!(cold_sig.as_slice(), expected.as_ref());
    }

    #[test]
    fn a_url_changed_after_signing_is_named_not_reported_as_a_bad_signature() {
        let cold = cold_key(7);
        let pk = [9u8; 32];
        let signed = sign(
            &SigningRequest::register("preprod", "7d21", "http://spo:8080", &pk, None, nonce()),
            &cold,
        )
        .expect("signing");

        let now =
            SigningRequest::register("preprod", "7d21", "http://spo:8080/", &pk, None, nonce());
        let err = signed.check(&now, None).expect_err("must refuse");

        assert!(err.contains("http://spo:8080/"), "{err}");
        assert!(err.contains("bifrost_url"), "{err}");
    }

    #[test]
    fn a_signed_exit_verifies_as_the_validator_would() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let req = SigningRequest::deregister("preprod", "7d21", &pool_id, nonce());

        let signed = sign(&req, &cold).expect("signing");

        let sig = RevocationSignature {
            cold_vkey: parse_hex(&signed.cold_vkey, "cold_vkey").unwrap(),
            cold_sig: parse_hex(&signed.cold_sig, "cold_sig").unwrap(),
            nonce: nonce(),
        };
        assert_eq!(verify_revocation(&sig).unwrap(), pool_id);
    }

    // ---- rev 5.6: the nonce ([REG-10], [DRG-6]) ---------------------------

    /// The replay the nonce exists to stop, on the file format's own terms: the
    /// node reserved a different UTxO than the one the signature covers, so the
    /// transaction it would build is not the one that was signed. Reported as
    /// the moved field, not as a signature that does not verify — which is the
    /// whole reason the response carries its request.
    #[test]
    fn a_nonce_that_moved_after_signing_is_named() {
        let cold = cold_key(7);
        let pk = [9u8; 32];
        let signed = sign(
            &SigningRequest::register("preprod", "7d21", "http://spo:8080", &pk, None, nonce()),
            &cold,
        )
        .expect("signing");

        let now = SigningRequest::register(
            "preprod",
            "7d21",
            "http://spo:8080",
            &pk,
            None,
            other_nonce(),
        );
        let err = signed.check(&now, None).expect_err("must refuse");

        assert!(err.contains("nonce_outpoint"), "{err}");
        assert!(err.contains(&other_nonce().to_string()), "{err}");
    }

    /// The same exit signature against a different nonce does not verify. This
    /// is the on-chain rejection, reproduced on the operator's own desk: before
    /// rev 5.6 an exit signature was valid against every later registration of
    /// the pool, from any wallet.
    #[test]
    fn an_exit_signature_does_not_verify_against_another_nonce() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let signed = sign(
            &SigningRequest::deregister("preprod", "7d21", &pool_id, nonce()),
            &cold,
        )
        .expect("signing");

        let replayed = RevocationSignature {
            cold_vkey: parse_hex(&signed.cold_vkey, "cold_vkey").unwrap(),
            cold_sig: parse_hex(&signed.cold_sig, "cold_sig").unwrap(),
            nonce: other_nonce(),
        };
        assert!(
            verify_revocation(&replayed).is_err(),
            "a revocation signature must not verify against an outpoint it does not name"
        );
    }

    /// A v1 file is refused BY NAME. Its signature covers the rev-5.5 preimage,
    /// which the chain no longer builds, so there is no transaction it could
    /// still authorize — accepting it would only move the failure to after a fee
    /// is spent.
    #[test]
    fn a_version_one_file_is_refused_with_the_reason() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let mut req = SigningRequest::deregister("preprod", "7d21", &pool_id, nonce());
        req.v = 1;

        let err = sign(&req, &cold).expect_err("must refuse");

        assert!(err.contains("sign again"), "{err}");
        assert!(err.contains("message format changed"), "{err}");
    }

    /// And a v1 RESPONSE is refused the same way, so an operator who kept a file
    /// from before the upgrade hears why rather than seeing a bad signature.
    #[test]
    fn a_version_one_response_is_refused_with_the_reason() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let req = SigningRequest::deregister("preprod", "7d21", &pool_id, nonce());
        let mut signed = sign(&req, &cold).expect("signing");
        signed.v = 1;

        let err = signed.check(&req, None).expect_err("must refuse");

        assert!(err.contains("sign again"), "{err}");
    }

    /// A request with the field missing cannot be signed at all: a shorter
    /// preimage is a rev-5.5 message, and signing one would produce a signature
    /// nothing on chain accepts.
    #[test]
    fn a_request_without_a_nonce_cannot_be_signed() {
        let cold = cold_key(7);
        let pool_id = pool_id_from_cold_vkey(&cold.public_key().into());
        let mut req = SigningRequest::deregister("preprod", "7d21", &pool_id, nonce());
        req.nonce_outpoint = None;

        let err = sign(&req, &cold).expect_err("must refuse");

        assert!(err.contains("nonce_outpoint"), "{err}");
    }

    /// The nonce survives the JSON round trip in the form the CLI prints.
    #[test]
    fn the_nonce_round_trips_as_txid_hash_index() {
        let req = SigningRequest::deregister("preprod", "7d21", &[0xab; 28], nonce());
        let back: SigningRequest =
            serde_json::from_str(&serde_json::to_string(&req).unwrap()).unwrap();
        assert_eq!(
            back.nonce_outpoint.as_deref(),
            Some(nonce().to_string().as_str())
        );
        assert_eq!(back.nonce().unwrap(), nonce());
        assert_eq!(nonce().to_string(), format!("{}#3", "7a".repeat(32)));
    }
}
