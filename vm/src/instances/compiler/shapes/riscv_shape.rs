use std::sync::Arc;

use crate::instances::compiler::shapes::ProofShape;
use hashbrown::{HashMap, HashSet};
use p3_field::PrimeField;
use serde::{Deserialize, Serialize};

use crate::{
    compiler::riscv::program::Program,
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode},
    machine::chip::ChipBehavior,
};
use thiserror::Error;

/// The shape of a riscv proof.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct RiscvPadShape {
    /// Keys are the chip names and values are the log-heights of the chips.
    pub inner: HashMap<String, usize>,
}

impl RiscvPadShape {
    /// Create a dummy program with this shape.
    ///
    /// This can be used to generate a dummy preprocessed traces.
    #[must_use]
    pub fn dummy_program(&self) -> Program {
        let mut program = Program::new(vec![], 1 << 5, 1 << 5);
        program.preprocessed_shape = Some(self.clone());
        program
    }

    /// Create a dummy execution record with this shape.
    ///
    /// This can be used to generate dummy traces.
    #[must_use]
    pub fn dummy_record(&self) -> EmulationRecord {
        let program = Arc::new(self.dummy_program());
        let mut record = EmulationRecord::new(program);
        record.shape = Some(self.clone());
        record
    }

    /// Determines whether the execution record contains a trace for a given chip.
    pub fn included<F: PrimeField, CB: ChipBehavior<F>>(&self, air: &CB) -> bool {
        self.inner.contains_key(&air.name())
    }
}

impl Extend<RiscvPadShape> for RiscvPadShape {
    fn extend<T: IntoIterator<Item = RiscvPadShape>>(&mut self, iter: T) {
        for shape in iter {
            self.inner.extend(shape.inner);
        }
    }
}

impl Extend<(String, usize)> for RiscvPadShape {
    fn extend<T: IntoIterator<Item = (String, usize)>>(&mut self, iter: T) {
        self.inner.extend(iter);
    }
}

impl IntoIterator for RiscvPadShape {
    type Item = (String, usize);

    type IntoIter = hashbrown::hash_map::IntoIter<String, usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl FromIterator<(String, usize)> for RiscvPadShape {
    fn from_iter<T: IntoIterator<Item = (String, usize)>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

impl From<ProofShape> for RiscvPadShape {
    fn from(value: ProofShape) -> Self {
        Self {
            inner: value.into_iter().collect(),
        }
    }
}

impl From<RiscvPadShape> for ProofShape {
    fn from(value: RiscvPadShape) -> Self {
        value.inner.into_iter().collect()
    }
}

impl PartialOrd for RiscvPadShape {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let set = self.inner.keys().collect::<HashSet<_>>();
        let other_set = other.inner.keys().collect::<HashSet<_>>();

        if set.is_subset(&other_set) {
            let mut less_seen = false;
            let mut greater_seen = false;
            for (name, &height) in self.inner.iter() {
                let other_height = other.inner[name];
                match height.cmp(&other_height) {
                    std::cmp::Ordering::Less => less_seen = true,
                    std::cmp::Ordering::Greater => greater_seen = true,
                    std::cmp::Ordering::Equal => {}
                }
            }
            if less_seen && greater_seen {
                return None;
            }

            if less_seen {
                return Some(std::cmp::Ordering::Less);
            }
        }

        if other_set.is_subset(&set) {
            let mut less_seen = false;
            let mut greater_seen = false;
            for (name, &height) in other.inner.iter() {
                let other_height = self.inner[name];
                match height.cmp(&other_height) {
                    std::cmp::Ordering::Less => less_seen = true,
                    std::cmp::Ordering::Greater => greater_seen = true,
                    std::cmp::Ordering::Equal => {}
                }
            }

            if less_seen && greater_seen {
                return None;
            }

            if greater_seen {
                return Some(std::cmp::Ordering::Greater);
            }
        }

        None
    }
}

#[derive(Debug, Error)]
pub enum RiscvShapeError {
    #[error("no preprocessed shape found")]
    PreprocessedShapeError,
    #[error("Preprocessed shape already fixed")]
    PreprocessedShapeAlreadyFixed,
}

// helper functions

// TODO: remove hardcode chip_names here
pub fn precompile_rows_per_event(chip_name: &str) -> usize {
    match chip_name {
        "ShaCompress" => 80,
        "ShaExtend" => 48,
        // 13.5 rows per permutation in the sliced layout (27 per two); rounded up.
        "KeccakPermute" => 14,
        _ => 1,
    }
}

/// The rows a precompile kind's own trace takes for `n` events, as its generator lays them out.
///
/// `n * rows_per_event` for every kind but KeccakPermute, whose sliced layout pairs permutations
/// into 27-row slots and pads to a power of two that avoids one wrap (`sliced_height`), so its
/// count is already the padded height. The MLE shapes key on this, not on the rounded
/// `precompile_rows_per_event`, so a whitelist shape is exactly what tracegen produces.
///
/// Blake2bRound's unit is a round, not a call: a call runs a caller-chosen number of rounds, one
/// row each, so its callers pass the round count ([`precompile_kind_units`]).
pub fn precompile_kind_rows(chip_name: &str, n: usize) -> usize {
    match chip_name {
        "KeccakPermute" => crate::chips::precompiles::keccak256::sliced::sliced_height(n),
        _ => n * precompile_rows_per_event(chip_name),
    }
}

/// The fixed-height lookup tables a precompile kind's chunk carries beside it: the sliced
/// Keccak's chi and xor5 tables, one 2^20-row AIR. Present exactly when the kind is.
pub fn precompile_tables(chip_name: &str) -> &'static [(&'static str, usize)] {
    match chip_name {
        "KeccakPermute" => &[("KeccakTables", 20)],
        _ => &[],
    }
}

/// What [`precompile_kind_rows`] counts for a kind over a record's events: the events, or for
/// Blake2bRound the rounds of its calls.
pub fn precompile_kind_units(
    chip_name: &str,
    events: &[(
        crate::emulator::riscv::syscalls::SyscallEvent,
        crate::emulator::riscv::syscalls::precompiles::PrecompileEvent,
    )],
) -> usize {
    use crate::emulator::riscv::syscalls::precompiles::PrecompileEvent;
    match chip_name {
        "Blake2bRound" => events
            .iter()
            .map(|(_, event)| match event {
                PrecompileEvent::Blake2bRounds(e) => e.rounds as usize,
                _ => unreachable!("a BLAKE2B_ROUNDS group holds another event"),
            })
            .sum(),
        _ => events.len(),
    }
}

// TODO: remove hardcode chip_names here
pub(crate) fn precompile_syscall_code(chip_name: &str) -> SyscallCode {
    match chip_name {
        "Blake2bControl" => SyscallCode::BLAKE2B_ROUNDS,
        "Blake2bRound" => SyscallCode::BLAKE2B_ROUNDS,
        "Bls12381AddAssign" => SyscallCode::BLS12381_ADD,
        "Bls12381Decompress" => SyscallCode::BLS12381_DECOMPRESS,
        "Bls12381DoubleAssign" => SyscallCode::BLS12381_DOUBLE,
        "Bls12381G2AddAssign" => SyscallCode::BLS12381_G2_ADD,
        "Bls12381G2DoubleAssign" => SyscallCode::BLS12381_G2_DOUBLE,
        "Bls381Fp2AddSub" => SyscallCode::BLS12381_FP2_ADD,
        "Bls381Fp2Mul" => SyscallCode::BLS12381_FP2_MUL,
        "Bls381FpOp" => SyscallCode::BLS12381_FP_ADD,
        "Bn254AddAssign" => SyscallCode::BN254_ADD,
        "Bn254DoubleAssign" => SyscallCode::BN254_DOUBLE,
        "Bn254Fp2AddSub" => SyscallCode::BN254_FP2_ADD,
        "Bn254Fp2Mul" => SyscallCode::BN254_FP2_MUL,
        "Bn254FpOp" => SyscallCode::BN254_FP_ADD,
        "EdAddAssign" => SyscallCode::ED_ADD,
        "EdDecompress" => SyscallCode::ED_DECOMPRESS,
        "KeccakPermute" => SyscallCode::KECCAK_PERMUTE,
        "KeccakControl" => SyscallCode::KECCAK_PERMUTE,
        "Poseidon2Permute" => SyscallCode::POSEIDON2_PERMUTE,
        "Secp256k1AddAssign" => SyscallCode::SECP256K1_ADD,
        "Secp256k1Decompress" => SyscallCode::SECP256K1_DECOMPRESS,
        "Secp256k1DoubleAssign" => SyscallCode::SECP256K1_DOUBLE,
        "Secp256k1FpOp" => SyscallCode::SECP256K1_FP_ADD,
        "Secp256r1AddAssign" => SyscallCode::SECP256R1_ADD,
        "Secp256r1Decompress" => SyscallCode::SECP256R1_DECOMPRESS,
        "Secp256r1DoubleAssign" => SyscallCode::SECP256R1_DOUBLE,
        "ShaCompress" => SyscallCode::SHA_COMPRESS,
        "ShaCompressControl" => SyscallCode::SHA_COMPRESS,
        "ShaExtend" => SyscallCode::SHA_EXTEND,
        "ShaExtendControl" => SyscallCode::SHA_EXTEND,
        "Uint256MulMod" => SyscallCode::UINT256_MUL,
        _ => {
            unreachable!("precompile {} not supported yet", chip_name);
        }
    }
}
