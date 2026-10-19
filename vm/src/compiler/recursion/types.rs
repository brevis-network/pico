// TODO: move parts of the code to compiler

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use pico_derive::AlignedBorrow;
use rand::{
    distr::{Distribution, StandardUniform},
    Rng, RngExt,
};
use serde::{Deserialize, Serialize};

use crate::{
    compiler::recursion::ir::Block,
    emulator::recursion::{emulator::*, public_values::RecursionPublicValues},
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS, HORNER_EVAL_DATAPAR},
};

pub const WIDTH: usize = 16;

#[derive(
    AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default,
)]
#[repr(transparent)]
pub struct Address<F>(pub F);

impl<F> Distribution<Address<F>> for StandardUniform
where
    StandardUniform: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Address<F> {
        Address(rng.random())
    }
}

impl<F: PrimeField64> Address<F> {
    #[inline]
    pub fn as_usize(&self) -> usize {
        self.0.as_canonical_u64() as usize
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the base field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

impl<F> Distribution<BaseAluIo<F>> for StandardUniform
where
    StandardUniform: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BaseAluIo<F> {
        BaseAluIo {
            out: rng.random(),
            in1: rng.random(),
            in2: rng.random(),
        }
    }
}

pub type BaseAluEvent<F> = BaseAluIo<F>;

/// An instruction invoking the base field ALU.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct BaseAluInstr<F> {
    pub opcode: BaseAluOpcode,
    pub mult: F,
    pub addrs: BaseAluIo<Address<F>>,
}

impl<F> Distribution<BaseAluInstr<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Address<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BaseAluInstr<F> {
        BaseAluInstr {
            opcode: rng.random(),
            mult: rng.random(),
            addrs: rng.random(),
        }
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to an operation of the extension field ALU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluIo<V> {
    pub out: V,
    pub in1: V,
    pub in2: V,
}

impl<F> Distribution<ExtAluIo<F>> for StandardUniform
where
    StandardUniform: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ExtAluIo<F> {
        ExtAluIo {
            out: rng.random(),
            in1: rng.random(),
            in2: rng.random(),
        }
    }
}

pub type ExtAluEvent<F> = ExtAluIo<Block<F>>;

/// An instruction invoking the extension field ALU.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtAluInstr<F> {
    pub opcode: ExtAluOpcode,
    pub mult: F,
    pub addrs: ExtAluIo<Address<F>>,
}

impl<F> Distribution<ExtAluInstr<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Address<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> ExtAluInstr<F> {
        ExtAluInstr {
            opcode: rng.random(),
            mult: rng.random(),
            addrs: rng.random(),
        }
    }
}

// -------------------------------------------------------------------------------------------------

/// The inputs and outputs to the manual memory management/memory initialization table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct MemIo<V> {
    pub inner: V,
}

impl<F> Distribution<MemIo<F>> for StandardUniform
where
    StandardUniform: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MemIo<F> {
        MemIo {
            inner: rng.random(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemInstr<F> {
    pub addrs: MemIo<Address<F>>,
    pub vals: MemIo<Block<F>>,
    pub mult: F,
    pub kind: MemAccessKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct MemInstrFfi<F> {
    pub addrs: MemIo<Address<F>>,
    pub vals: MemIo<Block<F>>,
    pub mult: F,
}

impl<F: Copy + core::ops::Neg<Output = F>> From<&MemInstr<F>> for MemInstrFfi<F> {
    fn from(value: &MemInstr<F>) -> Self {
        Self {
            addrs: value.addrs,
            vals: value.vals,
            mult: match value.kind {
                MemAccessKind::Read => -value.mult,
                MemAccessKind::Write => value.mult,
            },
        }
    }
}

impl<F: Copy + core::ops::Neg<Output = F>> From<MemInstr<F>> for MemInstrFfi<F> {
    fn from(value: MemInstr<F>) -> Self {
        Self::from(&value)
    }
}

impl<F> Distribution<MemInstr<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Address<F>> + Distribution<Block<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MemInstr<F> {
        MemInstr {
            addrs: rng.random(),
            vals: rng.random(),
            mult: rng.random(),
            kind: rng.random(),
        }
    }
}

// -------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MemAccessKind {
    Read,
    Write,
}

impl Distribution<MemAccessKind> for StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MemAccessKind {
        match rng.random_range(0..2) {
            0 => MemAccessKind::Read,
            1 => MemAccessKind::Write,
            _ => unreachable!(),
        }
    }
}

/// The inputs and outputs to a Poseidon2 permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2Io<V> {
    pub input: [V; WIDTH],
    pub output: [V; WIDTH],
}

/// An instruction invoking the Poseidon2 permutation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2SkinnyInstr<F> {
    pub addrs: Poseidon2Io<Address<F>>,
    pub mults: [F; WIDTH],
}

impl<F> Distribution<Poseidon2SkinnyInstr<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Address<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Poseidon2SkinnyInstr<F> {
        Poseidon2SkinnyInstr {
            addrs: Poseidon2Io {
                input: rng.random(),
                output: rng.random(),
            },
            mults: rng.random(),
        }
    }
}

pub type Poseidon2Event<F> = Poseidon2Io<F>;

/*
Select-related
 */

/// The inputs and outputs to a select operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectIo<V> {
    pub bit: V,
    pub out1: V,
    pub out2: V,
    pub in1: V,
    pub in2: V,
}

impl<F> Distribution<SelectIo<F>> for StandardUniform
where
    StandardUniform: Distribution<F>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SelectIo<F> {
        SelectIo {
            bit: rng.random(),
            out1: rng.random(),
            out2: rng.random(),
            in1: rng.random(),
            in2: rng.random(),
        }
    }
}

/// An instruction invoking the select operation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct SelectInstr<F> {
    pub addrs: SelectIo<Address<F>>,
    pub mult1: F,
    pub mult2: F,
}

impl<F> Distribution<SelectInstr<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Address<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SelectInstr<F> {
        SelectInstr {
            addrs: rng.random(),
            mult1: rng.random(),
            mult2: rng.random(),
        }
    }
}

/// The event encoding the inputs and outputs of a select operation.
pub type SelectEvent<F> = SelectIo<F>;

/*
ExpReverseBits-related
 */

/// The inputs and outputs to an exp-reverse-bits operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsIo<V> {
    pub base: V,
    // The bits of the exponent in little-endian order in a vec.
    pub exp: Vec<V>,
    pub result: V,
}

/// The inputs and outputs to an exp-reverse-bits operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ExpReverseBitsIoFfi<V> {
    pub base: V,
    pub result: V,
    pub len: usize,
    pub initial_row: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct ExpReverseBitsFfiEvent<F> {
    pub base: F,
    pub result: F,
    pub len: usize,
    pub initial_row: usize,
}

pub fn preprocess_exp_reverse_bits_instr_ffi<F: Copy>(
    instrs: &[&ExpReverseBitsInstr<F>],
) -> (Vec<ExpReverseBitsInstrFfi<F>>, Vec<Address<F>>) {
    let mut row = 0;
    (
        instrs
            .iter()
            .map(|inst| {
                let result = ExpReverseBitsInstrFfi {
                    addrs: ExpReverseBitsIoFfi {
                        base: inst.addrs.base,
                        result: inst.addrs.result,
                        len: inst.addrs.exp.len(),
                        initial_row: row,
                    },
                    mult: inst.mult,
                };
                row += result.addrs.len;
                result
            })
            .collect(),
        instrs
            .iter()
            .flat_map(|inst| inst.addrs.exp.iter().copied())
            .collect(),
    )
}

pub fn preprocess_exp_reverse_bits_ffi<F: Copy>(
    events: &[ExpReverseBitsEvent<F>],
) -> (Vec<ExpReverseBitsFfiEvent<F>>, Vec<F>) {
    let mut row = 0;
    (
        events
            .iter()
            .map(|event| {
                let result = ExpReverseBitsFfiEvent {
                    base: event.base,
                    result: event.result,
                    len: event.exp.len(),
                    initial_row: row,
                };
                row += result.len;
                result
            })
            .collect(),
        events
            .iter()
            .flat_map(|event| event.exp.iter().copied())
            .collect(),
    )
}

pub type Poseidon2Instr<F> = Poseidon2SkinnyInstr<F>;

/// An instruction invoking the exp-reverse-bits operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExpReverseBitsInstr<F> {
    pub addrs: ExpReverseBitsIo<Address<F>>,
    pub mult: F,
}

/// An FFI-safe instruction invoking the exp-reverse-bits operation.
#[derive(Clone, Debug)]
#[repr(C)]
pub struct ExpReverseBitsInstrFfi<F> {
    pub addrs: ExpReverseBitsIoFfi<Address<F>>,
    pub mult: F,
}

/// The event encoding the inputs and outputs of an exp-reverse-bits operation. The `len` operand is
/// now stored as the length of the `exp` field.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpReverseBitsEvent<F> {
    pub base: F,
    pub exp: Vec<F>,
    pub result: F,
}

/*
ExpBitsLen-related
 */

/// An instruction invoking the `ExpBitsLen` operation over the KoalaBear field.
///
/// Canonically bit-decomposes the field element read from `bit_src_in_addr` and computes
/// `result = base^(canonical(bit_src) mod 2^num_bits)`, writing `result` to `result_out_addr` and
/// the decomposition bits (LSB-first) to `bit_outs_addrs_mults`. `base` and `num_bits` are
/// program-fixed constants. Output mults are backfilled from `read_counts` in `convert.rs`'s
/// `finish()`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpBitsLenInstr<F> {
    /// Per-request base constant.
    pub base: F,
    /// Per-request decomposition width (number of low bits that affect `result`), `< 32`.
    pub num_bits: u32,
    /// Address of the field element to decompose (read once, on the first row).
    pub bit_src_in_addr: Address<F>,
    /// Address the final `result` is written to (written once, on the first row).
    pub result_out_addr: Address<F>,
    /// Write multiplicity for `result_out_addr` (backfilled in `finish()`).
    pub result_mult: F,
    /// Per-bit output addresses and write multiplicities (LSB-first; up to 31 entries, one per
    /// decomposition row). Mults are backfilled in `finish()`.
    pub bit_outs_addrs_mults: Vec<(Address<F>, F)>,
}

/// The event encoding the inputs of an `ExpBitsLen` operation. The decomposition bits and result
/// are recomputed from `base`/`bit_src`/`num_bits` during trace generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExpBitsLenEvent<F> {
    pub base: F,
    pub bit_src: F,
    pub num_bits: u32,
}

/*
BatchFRI-related
 */

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFRIIo<V> {
    pub ext_single: BatchFRIExtSingleIo<Block<V>>,
    pub ext_vec: BatchFRIExtVecIo<Vec<Block<V>>>,
    pub base_vec: BatchFRIBaseVecIo<V>,
}

/// The extension-field-valued single inputs to the batch FRI operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtSingleIo<V> {
    pub acc: V,
}

/// The extension-field-valued vector inputs to the batch FRI operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIExtVecIo<V> {
    pub p_at_z: V,
    pub alpha_pow: V,
}

/// The base-field-valued vector inputs to the batch FRI operation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIBaseVecIo<V> {
    pub p_at_x: V,
}

/// An instruction invoking the batch FRI operation. Addresses for extension field elements are of
/// the same type as for base field elements.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchFRIInstr<F> {
    pub base_vec_addrs: BatchFRIBaseVecIo<Vec<Address<F>>>,
    pub ext_single_addrs: BatchFRIExtSingleIo<Address<F>>,
    pub ext_vec_addrs: BatchFRIExtVecIo<Vec<Address<F>>>,
    pub acc_mult: F,
}

impl<F: PrimeCharacteristicRing> Distribution<BatchFRIInstr<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Address<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BatchFRIInstr<F> {
        let len = rng.random_range(4..8);
        let mut p_at_x = Vec::with_capacity(len);
        let mut p_at_z = Vec::with_capacity(len);
        let mut alpha_pow = Vec::with_capacity(len);
        for _ in 0..len {
            p_at_x.push(rng.random());
            p_at_z.push(rng.random());
            alpha_pow.push(rng.random());
        }
        BatchFRIInstr {
            base_vec_addrs: BatchFRIBaseVecIo { p_at_x },
            ext_single_addrs: BatchFRIExtSingleIo { acc: rng.random() },
            ext_vec_addrs: BatchFRIExtVecIo { p_at_z, alpha_pow },
            acc_mult: F::ONE,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct BatchFRIInstrFfi<F> {
    pub ext_single_addrs: BatchFRIExtSingleIo<Address<F>>,
    pub acc_mult: F,
    pub offset: usize,
    pub len: usize,
}

// preprocess into separate vectors instead of unpacking the vectors to optimize for memory
// allow: domain-complex signature — tuple reflects prover data-flow structure
#[allow(clippy::type_complexity)]
pub fn preprocess_batch_fri_ffi<F: Copy>(
    insts: &[impl AsRef<BatchFRIInstr<F>>],
) -> (
    Vec<BatchFRIInstrFfi<F>>,
    Vec<Address<F>>,
    Vec<Address<F>>,
    Vec<Address<F>>,
    bool,
    usize,
) {
    let mut offset = 0;
    let mut result = Vec::with_capacity(insts.len());
    let hueristic = insts
        .first()
        .map(|x| x.as_ref().base_vec_addrs.p_at_x.len())
        .unwrap_or_default();
    let mut good_heuristic = true;
    let mut p_at_x = Vec::with_capacity(hueristic * insts.len());
    let mut p_at_z = Vec::with_capacity(hueristic * insts.len());
    let mut alpha_pow = Vec::with_capacity(hueristic * insts.len());

    for inst in insts {
        let inst = inst.as_ref();
        assert_eq!(
            inst.base_vec_addrs.p_at_x.len(),
            inst.ext_vec_addrs.p_at_z.len()
        );
        assert_eq!(
            inst.ext_vec_addrs.p_at_z.len(),
            inst.ext_vec_addrs.alpha_pow.len()
        );
        let len = inst.base_vec_addrs.p_at_x.len();
        result.push(BatchFRIInstrFfi {
            ext_single_addrs: inst.ext_single_addrs,
            acc_mult: inst.acc_mult,
            offset,
            len,
        });
        p_at_x.extend_from_slice(&inst.base_vec_addrs.p_at_x);
        p_at_z.extend_from_slice(&inst.ext_vec_addrs.p_at_z);
        alpha_pow.extend_from_slice(&inst.ext_vec_addrs.alpha_pow);
        offset += len;

        if len != hueristic {
            good_heuristic = false;
        }
    }

    (result, p_at_x, p_at_z, alpha_pow, good_heuristic, offset)
}

/// The event encoding the data of a single iteration within the batch FRI operation.
/// For any given event, we are accessing a single element of the `Vec` inputs, so that the event
/// is not a type alias for `BatchFRIIo` like many of the other events.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BatchFRIEvent<F> {
    pub base_vec: BatchFRIBaseVecIo<F>,
    pub ext_single: BatchFRIExtSingleIo<Block<F>>,
    pub ext_vec: BatchFRIExtVecIo<Block<F>>,
}

impl<F> Distribution<BatchFRIEvent<F>> for StandardUniform
where
    StandardUniform: Distribution<F> + Distribution<Block<F>>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BatchFRIEvent<F> {
        BatchFRIEvent {
            base_vec: BatchFRIBaseVecIo {
                p_at_x: rng.random(),
            },
            ext_single: BatchFRIExtSingleIo { acc: rng.random() },
            ext_vec: BatchFRIExtVecIo {
                p_at_z: rng.random(),
                alpha_pow: rng.random(),
            },
        }
    }
}

/*
Public values-related
 */
/// An instruction that will save the public values to the execution record and will commit to
/// it's digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[repr(C)]
pub struct CommitPublicValuesInstr<F> {
    pub pv_addrs: RecursionPublicValues<Address<F>>,
}

/// The event for committing to the public values.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitPublicValuesEvent<F> {
    pub public_values: RecursionPublicValues<F>,
}

// ───────────────────────────── WHIR verifier chips ─────────────────────────────

/// Instruction for AssertZeroExtChip: asserts that the EF value at addr equals zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct AssertZeroExtInstr<F> {
    pub addr: Address<F>,
}

/// Event for AssertZeroExtChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct AssertZeroExtEvent<F> {
    pub val: Block<F>,
}

/// Instruction for FracFoldChip: (p1,q1)⊕(p2,q2) = (p1q2+p2q1, q1q2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct FracFoldInstr<F> {
    pub in_p1_addr: Address<F>,
    pub in_q1_addr: Address<F>,
    pub in_p2_addr: Address<F>,
    pub in_q2_addr: Address<F>,
    pub out_p_addr: Address<F>,
    pub out_q_addr: Address<F>,
    pub mult: F,
}

/// Event for FracFoldChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct FracFoldEvent<F> {
    pub p1: Block<F>,
    pub q1: Block<F>,
    pub p2: Block<F>,
    pub q2: Block<F>,
    pub out_p: Block<F>,
    pub out_q: Block<F>,
}

/// Instruction for UnivariateFoldChip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnivariateFoldInstr<F> {
    /// Addresses of the polynomial coefficients (ascending degree order).
    pub coeffs_addrs: Vec<Address<F>>,
    pub claimed_sum_addr: Address<F>,
    pub r_addr: Address<F>,
    pub next_sum_addr: Address<F>,
    pub mult: F,
}

/// Event for UnivariateFoldChip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnivariateFoldEvent<F> {
    /// Polynomial coefficients (padded to MAX_COEFFS by the chip).
    pub coeffs: Vec<Block<F>>,
    pub claimed_sum: Block<F>,
    pub r: Block<F>,
    pub next_sum: Block<F>,
}

/// Instruction for LagrangeEvalD2Chip: one degree-2 sumcheck round.
/// Reads claim, s1 = s(1), s2 = s(2), r; writes next_claim = p(r) where p is the
/// unique quadratic with p(0) = claim - s1, p(1) = s1, p(2) = s2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct LagrangeEvalD2Instr<F> {
    pub claim_addr: Address<F>,
    pub s1_addr: Address<F>,
    pub s2_addr: Address<F>,
    pub r_addr: Address<F>,
    pub next_claim_addr: Address<F>,
    pub mult: F,
}

/// Event for LagrangeEvalD2Chip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct LagrangeEvalD2Event<F> {
    pub claim: Block<F>,
    pub s1: Block<F>,
    pub s2: Block<F>,
    pub r: Block<F>,
    pub next_claim: Block<F>,
}

/// Instruction for GkrSumcheckRoundChip: one GKR cubic sumcheck sub-round.
/// Reads claim, s1 = s(1), s2 = s(2), s3 = s(3), challenge r, the previous round's
/// point coordinate xi, and the running eq product eq_in. Writes
/// next_claim = p(r) where p is the unique cubic with p(0) = claim - s1,
/// p(1) = s1, p(2) = s2, p(3) = s3, and eq_out = eq_in * eq_factor(xi, r).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct GkrSumcheckRoundInstr<F> {
    pub claim_addr: Address<F>,
    pub s1_addr: Address<F>,
    pub s2_addr: Address<F>,
    pub s3_addr: Address<F>,
    pub r_addr: Address<F>,
    pub xi_addr: Address<F>,
    pub eq_in_addr: Address<F>,
    pub next_claim_addr: Address<F>,
    pub eq_out_addr: Address<F>,
    pub mult_next: F,
    pub mult_eq: F,
}

/// Event for GkrSumcheckRoundChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct GkrSumcheckRoundEvent<F> {
    pub claim: Block<F>,
    pub s1: Block<F>,
    pub s2: Block<F>,
    pub s3: Block<F>,
    pub r: Block<F>,
    pub xi: Block<F>,
    pub eq_in: Block<F>,
    pub next_claim: Block<F>,
    pub eq_out: Block<F>,
}

/// Instruction for ExtDotProductChip: extension-field dot product with running
/// accumulator over PACKED base-field values.
/// `val_addrs[g]` points at one packed block whose EXTENSION_DEGREE lanes hold
/// EXTENSION_DEGREE base-field values; `mu_addrs[EXTENSION_DEGREE*g + k]` is the
/// mu for lane k (padding lanes use the zero address so they contribute 0).
/// Writes acc = sum_{g,k} val[g].lane_k * mu[g][k] to acc_addr. One instruction
/// spans len(val_addrs)/EXT_DOT_PRODUCT_GROUPS trace rows (the accumulator is
/// chained row-to-row), executing in one cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtDotProductInstr<F> {
    pub mu_addrs: Vec<Address<F>>,
    pub val_addrs: Vec<Address<F>>,
    pub acc_addr: Address<F>,
    pub mult: F,
}

/// Event for ExtDotProductChip (one per trace row of EXT_DOT_PRODUCT_GROUPS packed
/// value blocks x EXT_DOT_PRODUCT_DATAPAR mus, carrying the running acc AFTER this
/// row).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct ExtDotProductEvent<F> {
    pub mus: [Block<F>; EXT_DOT_PRODUCT_DATAPAR],
    pub vals: [Block<F>; EXT_DOT_PRODUCT_GROUPS],
    pub acc: Block<F>,
}

/// Instruction for HornerEvalChip: Horner evaluation of a univariate polynomial.
/// coeff_addrs are stored in EVALUATION order (highest degree first); the chip
/// chains acc = acc * x + coeff row-to-row and writes the final acc = P(x) to
/// out_addr. One instruction spans len(coeff_addrs) trace rows, one cycle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HornerEvalInstr<F> {
    /// Coefficient addresses, highest degree first.
    pub coeff_addrs: Vec<Address<F>>,
    pub x_addr: Address<F>,
    pub out_addr: Address<F>,
    pub mult: F,
}

/// Event for HornerEvalChip (one per trace row of DATAPAR coefficients in
/// evaluation order, carrying the running acc AFTER this row).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct HornerEvalEvent<F> {
    pub coeffs: [Block<F>; HORNER_EVAL_DATAPAR],
    pub x: Block<F>,
    pub acc: Block<F>,
}

/// Instruction for DigestSelectChip: bit-select of a full 8-lane digest.
/// Reads bit, in1[8] (h0), in2[8] (h1); writes out[i] = bit ? in2[i] : in1[i]
/// for all 8 lanes in one instruction/row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct DigestSelectInstr<F> {
    pub bit_addr: Address<F>,
    pub in1_addrs: [Address<F>; 2],
    pub in2_addrs: [Address<F>; 2],
    pub out_addrs: [Address<F>; 2],
    pub mults: [F; 2],
}

/// Event for DigestSelectChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct DigestSelectEvent<F> {
    pub bit: F,
    pub in1: [F; 8],
    pub in2: [F; 8],
    pub out: [F; 8],
}

/// Instruction for BinaryFoldStepChip: one WHIR binary k-fold butterfly step.
/// Reads tw, xi, inv_tw, xi_inv (base-field), alpha, v_lo, v_hi (EF); writes
///   out = v_lo + (alpha - tw*xi) * (v_lo - v_hi) * (inv_tw * xi_inv / 2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BinaryFoldStepInstr<F> {
    pub tw_addr: Address<F>,
    pub xi_addr: Address<F>,
    pub inv_tw_addr: Address<F>,
    pub xi_inv_addr: Address<F>,
    pub alpha_addr: Address<F>,
    pub v_lo_addr: Address<F>,
    pub v_hi_addr: Address<F>,
    pub out_addr: Address<F>,
    pub mult: F,
}

/// Event for BinaryFoldStepChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct BinaryFoldStepEvent<F> {
    pub tw: F,
    pub xi: F,
    pub inv_tw: F,
    pub xi_inv: F,
    pub alpha: Block<F>,
    pub v_lo: Block<F>,
    pub v_hi: Block<F>,
    pub out: Block<F>,
}

/// Instruction for PackBlockChip: packs 4 single base-field lanes into one Block.
/// Reads in_addrs[i].val[0] for i in 0..4 and writes Block([l0, l1, l2, l3]) to
/// out_addr in one instruction/row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct PackBlockInstr<F> {
    pub in_addrs: [Address<F>; 4],
    pub out_addr: Address<F>,
    pub mult: F,
}

/// Event for PackBlockChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct PackBlockEvent<F> {
    pub lanes: [F; 4],
}

/// Instruction for UnpackBlockChip: unpacks one Block into 4 single base-field
/// lanes. Reads the Block at in_addr and writes val.0[i] to out_addrs[i] for
/// i in 0..4 in one instruction/row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct UnpackBlockInstr<F> {
    pub in_addr: Address<F>,
    pub out_addrs: [Address<F>; 4],
    pub mults: [F; 4],
}

/// Event for UnpackBlockChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct UnpackBlockEvent<F> {
    pub val: Block<F>,
}

/// Instruction for Poseidon2PackedChip: a Poseidon2 permutation with packed
/// (Block-valued) I/O. Reads 4 input Blocks (16 lanes), permutes, and writes the
/// output back as 4 Blocks. Events reuse [`Poseidon2Event`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct Poseidon2PackedInstr<F> {
    pub input_addrs: [Address<F>; 4],
    pub output_addrs: [Address<F>; 4],
    pub mults: [F; 4],
}

/// Instruction for MleOpenChip.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct MleOpenInstr<F> {
    /// Encoded (air_id << 16 | col_id).
    pub col_ref: u32,
    pub opening_value_addr: Address<F>,
}

/// Event for MleOpenChip.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(C)]
pub struct MleOpenEvent<F> {
    pub col_ref: u32,
    pub opening_value: Block<F>,
}
