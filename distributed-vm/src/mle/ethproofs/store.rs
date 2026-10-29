//! Per-block proving results, and the `ProofInfo` the gRPC service hands back.
//!
//! Two properties here are deliberate departures from the FRI store this replaces:
//!
//! - **Reads are idempotent.** FRI answered `GetProveResult` with `take(block)`, so the first read
//!   removed the entry. That is fine while nothing goes wrong and a trap when something does: if we
//!   die mid-block and restart, the new process does not know that block, and RSP's
//!   `fetch_proving_status` has neither a timeout nor an attempt bound -- it polls a block nobody
//!   will ever answer, forever, without logging an error. Answering the same question twice with
//!   the same answer costs one retained entry.
//! - **Retention is bounded.** Idempotent reads are never consumed, and this process is meant to
//!   run for days at roughly one block per twenty minutes, so something has to evict. A small
//!   window suffices: RSP asks about the block it just submitted, never an old one.
//!
//! What a proved block is submitted as depends on the mode its root was proved in:
//!
//! - **Whitelist mode** (`VK_VERIFICATION=true`): v3, `PICOMLE\0` | 3 | zstd(bincode of
//!   [`MleRootProofV3`]). The root's vk travels with the proof, and a verifier accepts it only as a
//!   member of the whitelist it pins, so a party that trusts nothing the prover sent can check it.
//!   This is the one ethproofs can verify.
//! - **Otherwise**: v2, [`MleRootEnvelope`], which carries the root's child layouts instead. Those
//!   are trusted input (see `CombineMachine::preregister_root_shape`): forged layouts make the
//!   verifier keygen a circuit that constrains nothing. Fine between builds that trust each other,
//!   never for an untrusted verifier.

use crate::{mle::RootProofExport, ProofInfo, ProofType};
use dashmap::DashMap;
use prost_types::Duration as PbDuration;
use serde::{Deserialize, Serialize};
use std::{collections::VecDeque, sync::Mutex, time::Duration};
use tracing::{info, warn};

/// Layout version for [`MleRootEnvelope`].
///
/// The proof inside carries `mle-core`'s own codec version; this one covers the envelope's own
/// fields, so a decoder meeting a layout it does not know can refuse the bytes instead of
/// mis-reading them.
/// v2 compresses `child_layouts`; v1 carried them raw. Whitelist mode submits a different format,
/// [`ENVELOPE_V3`].
pub const ENVELOPE_VERSION: u32 = 2;

/// zstd level for the layouts.
///
/// 3 is zstd's own default and is not a considered choice so much as the absence of a reason to
/// spend longer: this runs once per block against a ~20 minute cadence, so even level 19 would be
/// free in wall-clock terms. Raise it if the measured size ever matters more than the ~ms spent.
const LAYOUT_ZSTD_LEVEL: i32 = 3;

/// The v2 submission, used outside whitelist mode: ethproofs receives base64 of `bincode` of this
/// in its `proof` field.
///
/// ⚠️ Only a verifier that trusts the prover can use it: the layouts below are compiled into the
/// verifier circuit, so forged ones make it constrain nothing. Anything that verifies on others'
/// behalf needs v3 ([`MleRootProofV3`]).
///
/// The proof bytes alone are NOT verifiable by anybody, which is why this type exists.
/// `CombineMachine::verify` checks a root against a verifying key the verifying machine keygen'd
/// ITSELF -- never the one it was handed -- so a verifier has to call
/// `register_shape(child_layouts, /* is_complete = */ true)` before it can check anything.
/// `RecursionVkLayout` is `Serialize` for exactly this reason; its own doc comment names the use
/// ("so a root proof can be handed to another build for verification").
#[derive(Serialize, Deserialize)]
pub struct MleRootEnvelope {
    pub version: u32,
    /// The combine root proof in `mle-core`'s canonical versioned wire format.
    pub proof: Vec<u8>,
    /// zstd of `bincode(Vec<RecursionVkLayout>)` -- the root node's ORDERED child layouts, where
    /// order is part of the shape rather than incidental.
    ///
    /// Compressed because they are the bulk of the envelope and they are extremely redundant:
    /// per-AIR structural records that repeat the same shapes across the tree. Uncompressed they
    /// more than DOUBLED what we submit -- measured at 448,059 proof bytes inside a 953,257-byte
    /// envelope -- which would have pushed a submission that is comfortably inside the 600 KiB
    /// target over it, on packaging rather than on anything cryptographic.
    ///
    /// The proof itself is deliberately left raw: it is already compact, it is the part a reader
    /// will want to inspect first, and `mle-core`'s codec is what defines its bytes.
    pub child_layouts_zstd: Vec<u8>,
    /// `RiscvVmVk::digest()` -- the guest-program identity the root is pinned against, so a
    /// verifier can confirm the proof belongs to the program it thinks it does.
    pub riscv_vk_digest: String,
}

/// Whitelist-mode submissions (`RootProofExport::root_vk` set) use v3 instead of
/// [`MleRootEnvelope`]: `PICOMLE\0` | 3 (u32 LE) | zstd(bincode([`MleRootProofV3`])), defined by
/// `pico_verifier::envelope`.
///
/// No layouts: v3 roots are proved in whitelist mode, so a verifier checks the root's vk against
/// the pinned whitelist instead of rebuilding it from layouts it would have to trust. The magic is
/// what routes these bytes to the MLE verifier inside ethproofs' `verify_stark("Pico", ..)`; the
/// FRI proofs sharing that entry are bincode and never start with it.
pub use pico_verifier::envelope::{MleRootProofV3, ENVELOPE_V3, PROOF_MAGIC};

fn encode_v3(body: &MleRootProofV3) -> Result<Vec<u8>, String> {
    pico_verifier::envelope::encode_v3(body).map_err(|e| e.to_string())
}

/// How many finished blocks stay answerable.
///
/// 64 is ~21 hours at the production cadence of one block per 100 (~20 minutes), which is far more
/// history than RSP ever asks for and small enough that the retained envelopes are not a leak.
fn result_capacity() -> usize {
    std::env::var("MLE_ETHPROOFS_RESULT_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(64)
}

pub struct ProvingResultStore {
    done: DashMap<u64, ProofInfo>,
    /// Insertion order, for eviction only -- `DashMap` has none of its own.
    order: Mutex<VecDeque<u64>>,
    capacity: usize,
}

impl Default for ProvingResultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ProvingResultStore {
    pub fn new() -> Self {
        let capacity = result_capacity();
        info!("ethproofs result store: last {capacity} block(s) stay answerable");
        Self {
            done: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            capacity,
        }
    }

    /// Record a proved block.
    ///
    /// Returns `false` when the envelope could not be serialized, in which case the block stays
    /// unanswerable and the caller has to report it as a failure -- storing a `ProofInfo` with
    /// empty proof bytes would instead make RSP submit an empty proof.
    pub fn complete(
        &self,
        block: u64,
        cycles: u64,
        proving: Duration,
        root: RootProofExport,
    ) -> bool {
        let verifier_id = root.riscv_vk_digest.clone();
        let proof_len = root.proof.len();

        if let Some(root_vk) = root.root_vk {
            let vk_len = root_vk.len();
            let body = MleRootProofV3 {
                proof: root.proof,
                root_vk,
            };
            return match encode_v3(&body) {
                Ok(bytes) => {
                    let parts = format!(
                        "v3 {} B = zstd(proof {proof_len} B + root vk {vk_len} B)",
                        bytes.len()
                    );
                    self.store(block, cycles, proving, bytes, verifier_id, &parts);
                    true
                }
                Err(e) => {
                    warn!("block {block}: v3 envelope failed; left unproved: {e}");
                    false
                }
            };
        }

        let layouts_raw = match bincode::serialize(&root.child_layouts) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("block {block}: child layouts would not serialize; left unproved: {e}");
                return false;
            }
        };
        let layouts_zstd = match zstd::encode_all(layouts_raw.as_slice(), LAYOUT_ZSTD_LEVEL) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("block {block}: child layouts would not compress; left unproved: {e}");
                return false;
            }
        };

        let layouts_raw_len = layouts_raw.len();
        let layouts_len = layouts_zstd.len();
        let envelope = MleRootEnvelope {
            version: ENVELOPE_VERSION,
            proof: root.proof,
            child_layouts_zstd: layouts_zstd,
            riscv_vk_digest: root.riscv_vk_digest,
        };
        let bytes = match bincode::serialize(&envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("block {block}: envelope serialization failed; left unproved: {e}");
                return false;
            }
        };

        let parts = format!(
            "envelope {} B = proof {proof_len} B + layouts {layouts_len} B \
             (from {layouts_raw_len} B, {:.1}x) + overhead",
            bytes.len(),
            layouts_raw_len as f64 / layouts_len.max(1) as f64,
        );
        self.store(block, cycles, proving, bytes, verifier_id, &parts);
        true
    }

    /// File a serialized submission as the answer for `block`.
    fn store(
        &self,
        block: u64,
        cycles: u64,
        proving: Duration,
        bytes: Vec<u8>,
        verifier_id: String,
        parts: &str,
    ) {
        // Floored at one millisecond. ethproofs rejects `proving_time = 0` with HTTP 400, and a
        // zero reaching this point would mean the duration was never measured rather than that a
        // block proved instantly -- so the floor turns a measurement bug into a visibly wrong
        // number instead of a rejected submission.
        let millis = proving.as_millis().max(1);
        let info = ProofInfo {
            block_number: block,
            proof_type: ProofType::Combine as i32,
            proof_with_publics: bytes,
            proving_cycles: cycles,
            verifier_id,
            proving_duration: Some(PbDuration {
                seconds: (millis / 1000) as i64,
                nanos: ((millis % 1000) * 1_000_000) as i32,
            }),
        };
        // Each part named, because only the total reaches ethproofs and the total alone cannot say
        // whether a size regression came from the proof or from the packaging around it.
        info!("block {block} answerable: {parts} | {cycles} cycle(s), {millis} ms");

        self.done.insert(block, info);
        let mut order = self.order.lock().expect("result order mutex poisoned");
        order.push_back(block);
        while order.len() > self.capacity {
            if let Some(evicted) = order.pop_front() {
                self.done.remove(&evicted);
            }
        }
    }

    /// The answer to `GetProveResult`. Repeatable on purpose -- see the module docs.
    pub fn get(&self, block: u64) -> Option<ProofInfo> {
        self.done.get(&block).map(|entry| entry.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(root_vk: Option<Vec<u8>>) -> RootProofExport {
        RootProofExport {
            proof: vec![7; 64],
            child_layouts: Vec::new(),
            riscv_vk_digest: "0xabc".into(),
            root_vk,
        }
    }

    /// The bytes a verifier decodes: the magic, the version as u32 LE, then zstd of the bincode
    /// of `MleRootProofV3`, proof first.
    #[test]
    fn whitelist_mode_submits_v3() {
        let store = ProvingResultStore::new();
        assert!(store.complete(1, 10, Duration::from_millis(5), root(Some(vec![9; 32]))));
        let info = store.get(1).expect("block 1 is answerable");
        let bytes = &info.proof_with_publics;
        assert_eq!(bytes[..8], PROOF_MAGIC);
        assert_eq!(
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            ENVELOPE_V3
        );
        let body: MleRootProofV3 =
            bincode::deserialize(&zstd::decode_all(&bytes[12..]).unwrap()).unwrap();
        assert_eq!(body.proof, vec![7; 64]);
        assert_eq!(body.root_vk, vec![9; 32]);
        assert_eq!(info.verifier_id, "0xabc");
    }

    /// Without a root vk the submission stays v2, whose first bytes are its version rather than
    /// the magic, so a decoder can tell the two apart.
    #[test]
    fn without_a_root_vk_submits_v2() {
        let store = ProvingResultStore::new();
        assert!(store.complete(2, 10, Duration::from_millis(5), root(None)));
        let bytes = store
            .get(2)
            .expect("block 2 is answerable")
            .proof_with_publics;
        assert_ne!(bytes[..8], PROOF_MAGIC);
        let envelope: MleRootEnvelope = bincode::deserialize(&bytes).unwrap();
        assert_eq!(envelope.version, ENVELOPE_VERSION);
        assert_eq!(envelope.proof, vec![7; 64]);
        assert_eq!(envelope.riscv_vk_digest, "0xabc");
    }
}
