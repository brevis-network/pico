//! Binding the guest's committed bytes to the proof that attests to them.
//!
//! A proof commits to `committed_value_digest`, the SHA-256 the guest accumulated over everything
//! it wrote to the public-values file descriptor. It does **not** commit to the bytes themselves,
//! so bytes stored beside a proof prove nothing about it until this module rehashes them.

use std::borrow::Borrow;

use pico_mle_core::p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_verifier::public_values;
use pico_vm::{
    compiler::word::Word,
    emulator::riscv::{public_values::PublicValues, record::EmulationRecord},
    mle::machine::{air::GCS_DIGEST_LEN, riscv::air_id},
    primitives::consts::{PV_DIGEST_NUM_WORDS, RISCV_NUM_PVS, WORD_SIZE},
};

use crate::{
    error::ProveError,
    phase::Phase,
    types::{InnerProof, Kb},
};

/// SHA-256 is 32 bytes; the AIR carries them one byte per field element.
const DIGEST_BYTES: usize = PV_DIGEST_NUM_WORDS * WORD_SIZE;

/// Read the digest out of a public-value vector at `indices`, each element holding one byte.
fn digest_at(
    pvs: &[Kb],
    indices: impl Iterator<Item = usize>,
    phase: Phase,
) -> Result<[u8; 32], ProveError> {
    let mut out = [0u8; DIGEST_BYTES];
    for (slot, index) in out.iter_mut().zip(indices) {
        let raw = pvs
            .get(index)
            .ok_or_else(|| ProveError::verification(phase, "public values too short for a digest"))?
            .as_canonical_u32();
        *slot = u8::try_from(raw).map_err(|_| {
            ProveError::verification(phase, format!("digest limb {index} is {raw}, not a byte"))
        })?;
    }
    Ok(out)
}

/// Fold one more proof's digest into what a set of proofs attests to.
///
/// A proof covering only chunks before the guest's COMMIT ecalls carries zero, and every proof
/// covering a later chunk carries the final digest. So a set is read by taking the nonzero copies
/// and requiring them to agree — the host-side mirror of the in-circuit consistency check, where a
/// nonzero accumulator forces every nonzero child equal. Taking any one proof's copy would read zero
/// on a run whose first chunk precedes the commit.
fn agree(seen: [u8; 32], next: [u8; 32], phase: Phase) -> Result<[u8; 32], ProveError> {
    const ZERO: [u8; 32] = [0u8; 32];
    match (seen, next) {
        (_, ZERO) => Ok(seen),
        (ZERO, _) => Ok(next),
        _ if seen == next => Ok(seen),
        _ => Err(ProveError::verification(
            phase,
            "proofs disagree on committed_value_digest",
        )),
    }
}

/// Give every record that carries a nonzero digest the run's final one.
///
/// The guest's COMMIT ecalls write the digest one word per call, and the emulator can end a chunk
/// between two of them, leaving the earlier chunk a partial digest that the combine layer's
/// consistency check rejects in an honest run. Replacing it is sound: a chunk's constraints bind
/// only the words committed inside it, and those already equal the final digest's.
pub(crate) fn backfill_final_digests(records: &mut [EmulationRecord]) {
    let Some(last) = records.last() else {
        return;
    };
    let committed = last.public_values.committed_value_digest;
    let deferred = last.public_values.deferred_proofs_digest;
    for pvs in records.iter_mut().map(|record| &mut record.public_values) {
        if pvs.committed_value_digest.iter().any(|&w| w != 0) {
            pvs.committed_value_digest = committed;
        }
        if pvs.deferred_proofs_digest.iter().any(|&w| w != 0) {
            pvs.deferred_proofs_digest = deferred;
        }
    }
}

/// Whether the guest ran the COMMIT ecall: some record carries a nonzero digest.
#[cfg(feature = "multi-field-transcript")]
pub(crate) fn commits(records: &[EmulationRecord]) -> bool {
    records.iter().any(|record| {
        record
            .public_values
            .committed_value_digest
            .iter()
            .any(|&w| w != 0)
    })
}

/// Refuse a RISC-V bundle any of whose chunks lacks its global cumulative sum.
///
/// `verify_riscv` reads each chunk's sum out of the Global AIR's public values and aborts when they
/// are short. That AIR is optional in the key, so a chunk proof that omits it still passes its
/// STARK verify; a bundle from a file is checked here first.
pub(crate) fn ensure_chunk_gcs<'a>(
    chunks: impl Iterator<Item = &'a [Vec<Kb>]>,
) -> Result<(), ProveError> {
    for (chunk, pv_sets) in chunks.enumerate() {
        let len = pv_sets.get(air_id::GLOBAL).map_or(0, Vec::len);
        if len < GCS_DIGEST_LEN {
            return Err(ProveError::verification(
                Phase::Riscv,
                format!(
                    "chunk {chunk}: {len} Global AIR public value(s), too few for its global \
                     cumulative sum"
                ),
            ));
        }
    }
    Ok(())
}

/// The AIRs `build_ctx` hands a copy of the chunk's RISC-V public values at offset zero. The Global
/// AIR carries one more, after its global cumulative sum.
const RISCV_PV_AIRS: [usize; 4] = [
    air_id::CPU,
    air_id::ECALL,
    air_id::MEM_INIT,
    air_id::MEM_FINAL,
];

/// Refuse a RISC-V bundle any of whose chunks carries a non-zero exit code.
///
/// Every chunk, and every copy of the RISC-V public values in it, is read: which copies a chunk
/// carries depends on its shape, so no one copy stands for the run.
pub(crate) fn ensure_exit_code_zero<'a>(
    chunks: impl Iterator<Item = &'a [Vec<Kb>]>,
) -> Result<(), ProveError> {
    for (chunk, pv_sets) in chunks.enumerate() {
        let global = pv_sets
            .get(air_id::GLOBAL)
            .and_then(|pvs| pvs.get(GCS_DIGEST_LEN..))
            .unwrap_or_default();
        let others = RISCV_PV_AIRS
            .iter()
            .filter_map(|&id| pv_sets.get(id))
            .filter(|pvs| !pvs.is_empty())
            .map(Vec::as_slice);
        for copy in std::iter::once(global).chain(others) {
            let exit_code = exit_code_of(copy).ok_or_else(|| {
                ProveError::verification(
                    Phase::Riscv,
                    format!("chunk {chunk}: a copy of the RISC-V public values has no exit code"),
                )
            })?;
            if exit_code != 0 {
                return Err(ProveError::NonZeroExitCode { chunk, exit_code });
            }
        }
    }
    Ok(())
}

/// `exit_code`, read through the VM's own public-value layout; `None` if `copy` is shorter than it.
fn exit_code_of(copy: &[Kb]) -> Option<u32> {
    let pvs: &PublicValues<Word<Kb>, Kb> = copy.get(..RISCV_NUM_PVS)?.borrow();
    Some(pvs.exit_code.as_canonical_u32())
}

/// Each proof's public-value sets, the form every check here reads.
pub(crate) fn public_values(proofs: &[InnerProof]) -> impl Iterator<Item = &[Vec<Kb>]> {
    proofs.iter().map(|p| p.public_values.as_slice())
}

/// The digest a RISC-V chunk bundle attests to.
pub(crate) fn riscv_committed_digest(chunks: &[InnerProof]) -> Result<[u8; 32], ProveError> {
    riscv_committed_digest_over(public_values(chunks))
}

/// The digest a RISC-V bundle attests to, read from the Ecall air's copy of the public values: it
/// is the one copy the digest is constrained in, the others (Cpu's among them) being free there.
/// Only chunks that executed instructions carry that air — a deferred-split record has no Ecall
/// trace, so its vector is empty and is passed over. An all-zero result means the guest never
/// committed.
fn riscv_committed_digest_over<'a>(
    chunks: impl Iterator<Item = &'a [Vec<Kb>]>,
) -> Result<[u8; 32], ProveError> {
    let mut found = [0u8; 32];
    let mut saw_ecall = false;
    for pv_sets in chunks {
        let Some(ecall) = pv_sets
            .get(air_id::ECALL)
            .filter(|pvs| pvs.len() >= DIGEST_BYTES)
        else {
            continue;
        };
        saw_ecall = true;
        found = agree(
            found,
            digest_at(ecall, 0..DIGEST_BYTES, Phase::Riscv)?,
            Phase::Riscv,
        )?;
    }
    if !saw_ecall {
        return Err(ProveError::verification(
            Phase::Riscv,
            "no chunk proof carries Ecall public values",
        ));
    }
    Ok(found)
}

/// The digest a set of recursion proofs attests to. See [`agree`]: reading `proofs[0]` would return
/// zero on any run whose halting chunk is not the first.
pub(crate) fn recursion_committed_digest_over<'a>(
    pv_sets: impl Iterator<Item = &'a [Vec<Kb>]>,
    phase: Phase,
) -> Result<[u8; 32], ProveError> {
    let mut found = [0u8; 32];
    for set in pv_sets {
        found = agree(found, recursion_committed_digest(set, phase)?, phase)?;
    }
    Ok(found)
}

/// The digest one recursion proof attests to.
pub(crate) fn recursion_committed_digest(
    pv_sets: &[Vec<Kb>],
    phase: Phase,
) -> Result<[u8; 32], ProveError> {
    let refused = |e: pico_verifier::VerifyError| ProveError::verification(phase, e.to_string());
    let pvs = public_values::recursion_public_values(pv_sets).map_err(refused)?;
    public_values::committed_value_digest(pvs).map_err(refused)
}

/// Output bytes [`rebind`] accepted against the digest a proof attests to. Only `rebind` makes
/// one, so a [`crate::Proof`] built from it cannot carry bytes its proof does not cover.
pub(crate) struct Bound {
    committed: Vec<u8>,
    digest: [u8; 32],
}

impl Bound {
    pub(crate) fn into_parts(self) -> (Vec<u8>, [u8; 32]) {
        (self.committed, self.digest)
    }
}

/// Accept `committed` as this proof's output, or reject it.
///
/// An all-zero digest is a guest that never ran the COMMIT ecall: it attests to no output, so the
/// only bytes it can be paired with are none.
pub(crate) fn rebind(committed: Vec<u8>, digest: [u8; 32]) -> Result<Bound, ProveError> {
    if public_values::committed_values_bound(&committed, &digest) {
        Ok(Bound { committed, digest })
    } else {
        Err(ProveError::CommittedValuesUnbound)
    }
}

/// The complete-root flag, read before anything expensive runs.
pub(crate) fn is_complete_root(pv_sets: &[Vec<Kb>]) -> bool {
    public_values::recursion_public_values(pv_sets)
        .is_ok_and(|pvs| pvs[public_values::RECURSION_PV_OFFSETS.flag_complete] == Kb::ONE)
}

#[cfg(test)]
mod tests {
    use pico_vm::{
        emulator::recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
        primitives::consts::RECURSION_NUM_PVS,
    };
    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn rebinding_accepts_only_the_bytes_the_digest_covers() {
        let bytes = b"the guest wrote this".to_vec();
        let digest: [u8; 32] = Sha256::digest(&bytes).into();

        rebind(bytes.clone(), digest).expect("honest bytes must bind");

        let mut forged = bytes.clone();
        forged[0] ^= 1;
        assert!(matches!(
            rebind(forged, digest),
            Err(ProveError::CommittedValuesUnbound)
        ));
        assert!(matches!(
            rebind(Vec::new(), digest),
            Err(ProveError::CommittedValuesUnbound)
        ));
    }

    /// The fold takes the nonzero copies whatever order they arrive in, and refuses a set whose
    /// nonzero copies disagree.
    #[test]
    fn the_fold_reads_the_only_chunk_that_carries_the_digest() {
        let zero = [0u8; 32];
        let a: [u8; 32] = Sha256::digest(b"a").into();
        let b: [u8; 32] = Sha256::digest(b"b").into();

        let p = Phase::Convert;
        assert_eq!(
            agree(zero, a, p).unwrap(),
            a,
            "the halting chunk arrived last"
        );
        assert_eq!(agree(a, zero, p).unwrap(), a, "it arrived first");
        assert_eq!(agree(a, a, p).unwrap(), a);
        assert_eq!(agree(zero, zero, p).unwrap(), zero, "nothing was committed");
        assert!(matches!(
            agree(a, b, p),
            Err(ProveError::Verification {
                phase: Phase::Convert,
                ..
            })
        ));
    }

    /// A guest that never committed attests to nothing, and bytes cannot be attached to it.
    #[test]
    fn a_zero_digest_admits_no_bytes() {
        rebind(Vec::new(), [0u8; 32]).expect("no output, no bytes");
        assert!(matches!(
            rebind(b"forged".to_vec(), [0u8; 32]),
            Err(ProveError::CommittedValuesUnbound)
        ));
    }

    /// A chunk whose Global AIR carries no values, too few, or no slot at all is refused by name.
    #[test]
    fn a_chunk_without_its_global_cumulative_sum_is_refused() {
        let with_global = |len: usize| {
            let mut sets = vec![Vec::new(); air_id::GLOBAL + 1];
            sets[air_id::GLOBAL] = vec![Kb::ZERO; len];
            sets
        };
        let whole = with_global(GCS_DIGEST_LEN);
        ensure_chunk_gcs([whole.as_slice()].into_iter()).expect("a whole sum is accepted");

        for (case, sets) in [
            ("empty", with_global(0)),
            ("short", with_global(GCS_DIGEST_LEN - 1)),
            ("no slot", vec![Vec::new(); air_id::GLOBAL]),
        ] {
            let err =
                ensure_chunk_gcs([whole.as_slice(), sets.as_slice()].into_iter()).expect_err(case);
            assert!(
                matches!(&err, ProveError::Verification { phase: Phase::Riscv, message } if message.starts_with("chunk 1:")),
                "{case}: {err}"
            );
        }
    }

    /// The digest is read from the Ecall copy, the one it is constrained in: a Cpu copy carrying
    /// a different digest does not move it.
    #[test]
    fn the_riscv_digest_is_read_from_the_ecall_copy() {
        let honest: [u8; 32] = Sha256::digest(b"honest").into();
        let forged: [u8; 32] = Sha256::digest(b"forged").into();
        let with_digest = |d: [u8; 32]| -> Vec<Kb> {
            let mut pvs = vec![Kb::ZERO; RISCV_NUM_PVS];
            for (slot, byte) in pvs.iter_mut().zip(d) {
                *slot = Kb::from_u8(byte);
            }
            pvs
        };
        let mut sets = vec![Vec::new(); air_id::ECALL + 1];
        sets[air_id::CPU] = with_digest(forged);
        sets[air_id::ECALL] = with_digest(honest);
        assert_eq!(
            riscv_committed_digest_over([sets.as_slice()].into_iter()).unwrap(),
            honest
        );

        let no_ecall = vec![Vec::new(); air_id::ECALL + 1];
        assert!(riscv_committed_digest_over([no_ecall.as_slice()].into_iter()).is_err());
    }

    /// A chunk's RISC-V public values with `exit_code` set, as the VM writes them.
    fn riscv_pvs(exit_code: u32) -> Vec<Kb> {
        PublicValues::<u32, u32> {
            exit_code,
            ..Default::default()
        }
        .to_vec()
    }

    /// A chunk that ran the CPU and an ecall, each copy with its own exit code.
    fn cpu_chunk(global: u32, cpu: u32, ecall: u32) -> Vec<Vec<Kb>> {
        let mut sets = vec![Vec::new(); air_id::ECALL + 1];
        sets[air_id::GLOBAL] = [vec![Kb::ZERO; GCS_DIGEST_LEN], riscv_pvs(global)].concat();
        sets[air_id::CPU] = riscv_pvs(cpu)[..RISCV_NUM_PVS].to_vec();
        sets[air_id::ECALL] = riscv_pvs(ecall)[..RISCV_NUM_PVS].to_vec();
        sets
    }

    /// A chunk with no CPU rows: memory finalization only.
    fn memory_chunk(global: u32, finalize: u32) -> Vec<Vec<Kb>> {
        let mut sets = vec![Vec::new(); air_id::GLOBAL + 1];
        sets[air_id::GLOBAL] = [vec![Kb::ZERO; GCS_DIGEST_LEN], riscv_pvs(global)].concat();
        sets[air_id::MEM_FINAL] = riscv_pvs(finalize);
        sets
    }

    fn check(chunks: &[Vec<Vec<Kb>>]) -> Result<(), ProveError> {
        ensure_exit_code_zero(chunks.iter().map(Vec::as_slice))
    }

    #[test]
    fn a_run_whose_every_chunk_exits_zero_is_accepted() {
        check(&[cpu_chunk(0, 0, 0), cpu_chunk(0, 0, 0), memory_chunk(0, 0)])
            .expect("every copy of every chunk says 0");
    }

    /// Refused whichever copy says so, including one that disagrees with the other two.
    #[test]
    fn a_non_zero_exit_on_the_halting_chunk_is_refused() {
        for (case, halting) in [
            ("every copy", cpu_chunk(3, 3, 3)),
            ("the ecall copy only", cpu_chunk(0, 0, 3)),
            ("the carrier only", cpu_chunk(3, 0, 0)),
        ] {
            let err = check(&[cpu_chunk(0, 0, 0), halting, memory_chunk(0, 0)]).expect_err(case);
            assert!(
                matches!(
                    err,
                    ProveError::NonZeroExitCode {
                        chunk: 1,
                        exit_code: 3
                    }
                ),
                "{case}: {err}"
            );
        }
    }

    /// A chunk with no CPU rows is checked too, copy by copy.
    #[test]
    fn a_non_zero_exit_on_a_chunk_without_cpu_rows_is_refused() {
        for (case, memory) in [
            ("both copies", memory_chunk(1, 1)),
            ("the carrier only", memory_chunk(1, 0)),
            ("the finalize copy only", memory_chunk(0, 1)),
        ] {
            let err = check(&[cpu_chunk(0, 0, 0), memory]).expect_err(case);
            assert!(
                matches!(
                    err,
                    ProveError::NonZeroExitCode {
                        chunk: 1,
                        exit_code: 1
                    }
                ),
                "{case}: {err}"
            );
        }
    }

    /// A chunk carrying no Global copy has no exit code to read, which is a refusal, not a pass.
    #[test]
    fn a_chunk_without_the_global_copy_is_refused() {
        let mut chunk = cpu_chunk(0, 0, 0);
        chunk[air_id::GLOBAL].truncate(GCS_DIGEST_LEN);
        let err = check(&[chunk]).expect_err("no exit code to read");
        assert!(
            matches!(&err, ProveError::Verification { phase: Phase::Riscv, message } if message.starts_with("chunk 0:")),
            "{err}"
        );
    }

    #[test]
    fn the_complete_flag_is_read_from_the_recursion_public_values() {
        let one_set = |flag: Kb| {
            let mut pvs = vec![Kb::ZERO; RECURSION_NUM_PVS];
            pvs[RECURSION_PUBLIC_VALUES_COL_MAP.flag_complete] = flag;
            vec![pvs]
        };

        assert!(is_complete_root(&one_set(Kb::ONE)));
        assert!(!is_complete_root(&one_set(Kb::ZERO)));
        assert!(!is_complete_root(&[]));
        assert!(
            !is_complete_root(&[vec![Kb::ONE; RECURSION_NUM_PVS - 1]]),
            "a set of another width is not the recursion layer's"
        );
    }

    /// A record left with a partial digest takes the final one, a record with none keeps none, and
    /// the deferred-proofs digest is treated alike.
    #[test]
    fn the_backfill_gives_every_committing_record_the_final_digests() {
        let digests = |committed: u32, deferred: u32| {
            let mut record = EmulationRecord::default();
            record.public_values.committed_value_digest = [committed; 8];
            record.public_values.deferred_proofs_digest = [deferred; 8];
            record
        };
        let mut records = vec![digests(1, 0), digests(0, 2), digests(3, 4)];
        backfill_final_digests(&mut records);
        let read: Vec<_> = records
            .iter()
            .map(|r| {
                let pvs = r.public_values;
                (pvs.committed_value_digest, pvs.deferred_proofs_digest)
            })
            .collect();
        assert_eq!(
            read,
            vec![([3; 8], [0; 8]), ([0; 8], [4; 8]), ([3; 8], [4; 8])]
        );

        backfill_final_digests(&mut []);
    }

    /// A recursion proof's digest is read from its recursion public values, a byte per element:
    /// the set of the wrong width is passed over, and a limb past a byte is refused.
    #[test]
    fn the_recursion_digest_is_read_byte_by_byte_from_the_recursion_public_values() {
        let digest: [u8; 32] = Sha256::digest(b"output").into();
        let with_digest = |bytes: [u32; 32]| {
            let mut pvs = vec![Kb::ZERO; RECURSION_NUM_PVS];
            let slots = RECURSION_PUBLIC_VALUES_COL_MAP
                .committed_value_digest
                .iter()
                .flat_map(|w| w.0);
            for (slot, byte) in slots.zip(bytes) {
                pvs[slot] = Kb::from_u32(byte);
            }
            vec![vec![Kb::ONE; RECURSION_NUM_PVS - 1], pvs]
        };
        let honest = with_digest(digest.map(u32::from));
        let p = Phase::Combine;

        assert_eq!(recursion_committed_digest(&honest, p).unwrap(), digest);
        let none = with_digest([0; 32]);
        assert_eq!(
            recursion_committed_digest_over([none.as_slice(), honest.as_slice()].into_iter(), p)
                .unwrap(),
            digest
        );

        let mut wide = digest.map(u32::from);
        wide[5] = 256;
        let err = recursion_committed_digest(&with_digest(wide), p).expect_err("not a byte");
        assert!(
            matches!(&err, ProveError::Verification { phase: Phase::Combine, message } if message.contains("not a byte")),
            "{err}"
        );
        assert!(recursion_committed_digest(&honest[..1], p).is_err());
    }

    /// The early refusal of a guest that never commits reads the emulated records.
    #[cfg(feature = "multi-field-transcript")]
    #[test]
    fn a_run_commits_when_any_record_carries_a_digest() {
        let mut records = vec![EmulationRecord::default(); 3];
        assert!(!commits(&records));
        records[1].public_values.committed_value_digest[5] = 1;
        assert!(commits(&records));
    }
}
