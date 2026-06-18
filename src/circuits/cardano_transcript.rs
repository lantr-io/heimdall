//! Cardano-friendly Blake2b Fiat-Shamir transcript for Halo2/KZG proofs.
//!
//! The default halo2 transcripts hash with Keccak/Poseidon; a Plutus
//! on-chain verifier can only cheaply recompute `blake2b_256`. This
//! transcript drives the Fiat-Shamir challenge off an *accumulated* byte
//! string hashed with `blake2b_256` (and a `blake2b_256(blake2b_256(..))`
//! re-hash to widen the squeeze to 64 bytes), so the prover here and the
//! eventual on-chain verifier derive identical challenges.
//!
//! Relocated from `benches/cardano_transcript.rs` (WI-019): proof
//! generation is no longer bench-only — `circuits::fault_evidence` produces
//! real DKG fault proofs from the library, and the benches now import this
//! module from the crate instead of carrying their own copy.

use std::{
    io::{self, Read, Write},
    marker::PhantomData,
};

use blake2b_simd::Params as Blake2bParams;
use halo2_base::halo2_proofs::{
    halo2curves::{
        CurveAffine,
        ff::{FromUniformBytes, PrimeField},
    },
    transcript::{
        Challenge255, EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer,
        TranscriptWrite, TranscriptWriterBuffer,
    },
};

const PREFIX_CHALLENGE: u8 = 0;
const PREFIX_COMMON: u8 = 1;

#[derive(Debug, Clone)]
pub struct CardanoBlake2bRead<R: Read, C: CurveAffine> {
    accumulated: Vec<u8>,
    reader: R,
    _marker: PhantomData<C>,
}

#[derive(Debug, Clone)]
pub struct CardanoBlake2bWrite<W: Write, C: CurveAffine> {
    accumulated: Vec<u8>,
    writer: W,
    _marker: PhantomData<C>,
}

fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    let digest = Blake2bParams::new().hash_length(32).hash(bytes);
    digest.as_bytes().try_into().expect("digest is 32 bytes")
}

fn challenge_input(accumulated: &mut Vec<u8>) -> [u8; 64] {
    accumulated.push(PREFIX_CHALLENGE);
    let hash = blake2b_256(accumulated);
    let rehash = blake2b_256(&hash);
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(&hash);
    input[32..].copy_from_slice(&rehash);
    input
}

fn append_common(accumulated: &mut Vec<u8>, bytes: &[u8]) {
    accumulated.push(PREFIX_COMMON);
    accumulated.extend_from_slice(bytes);
}

impl<R: Read, C: CurveAffine> TranscriptReadBuffer<R, C, Challenge255<C>>
    for CardanoBlake2bRead<R, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn init(reader: R) -> Self {
        Self {
            accumulated: Vec::new(),
            reader,
            _marker: PhantomData,
        }
    }
}

impl<W: Write, C: CurveAffine> TranscriptWriterBuffer<W, C, Challenge255<C>>
    for CardanoBlake2bWrite<W, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn init(writer: W) -> Self {
        Self {
            accumulated: Vec::new(),
            writer,
            _marker: PhantomData,
        }
    }

    fn finalize(self) -> W {
        self.writer
    }
}

impl<R: Read, C: CurveAffine> Transcript<C, Challenge255<C>> for CardanoBlake2bRead<R, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        Challenge255::new(&challenge_input(&mut self.accumulated))
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        append_common(&mut self.accumulated, point.to_bytes().as_ref());
        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        append_common(&mut self.accumulated, scalar.to_repr().as_ref());
        Ok(())
    }
}

impl<W: Write, C: CurveAffine> Transcript<C, Challenge255<C>> for CardanoBlake2bWrite<W, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn squeeze_challenge(&mut self) -> Challenge255<C> {
        Challenge255::new(&challenge_input(&mut self.accumulated))
    }

    fn common_point(&mut self, point: C) -> io::Result<()> {
        append_common(&mut self.accumulated, point.to_bytes().as_ref());
        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        append_common(&mut self.accumulated, scalar.to_repr().as_ref());
        Ok(())
    }
}

impl<R: Read, C: CurveAffine> TranscriptRead<C, Challenge255<C>> for CardanoBlake2bRead<R, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn read_point(&mut self) -> io::Result<C> {
        let mut compressed = C::Repr::default();
        self.reader.read_exact(compressed.as_mut())?;
        let point = Option::from(C::from_bytes(&compressed)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid point encoding in proof",
            )
        })?;
        append_common(&mut self.accumulated, compressed.as_ref());
        Ok(point)
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let mut repr = <C::Scalar as PrimeField>::Repr::default();
        self.reader.read_exact(repr.as_mut())?;
        let scalar = Option::from(C::Scalar::from_repr(repr)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid scalar encoding in proof",
            )
        })?;
        append_common(&mut self.accumulated, repr.as_ref());
        Ok(scalar)
    }
}

impl<W: Write, C: CurveAffine> TranscriptWrite<C, Challenge255<C>> for CardanoBlake2bWrite<W, C>
where
    C::Scalar: FromUniformBytes<64>,
{
    fn write_point(&mut self, point: C) -> io::Result<()> {
        let compressed = point.to_bytes();
        append_common(&mut self.accumulated, compressed.as_ref());
        self.writer.write_all(compressed.as_ref())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        let repr = scalar.to_repr();
        append_common(&mut self.accumulated, repr.as_ref());
        self.writer.write_all(repr.as_ref())
    }
}
