//! Recursion verifier-circuit lowering.
//!
//! The shared `Builder` circuit-construction vocabulary (IR / transcript / septic-field / MLE
//! evaluators, split across the `builder_*` submodules) plus the per-proof `verify_one` core that
//! lowers "verify a child STARK proof" into a recursion DSL program. This machinery is
//! recursion-phase-generic — any layer that verifies a child proof lowers through it. `Convert`
//! (single-proof leaf recursion) and `Combine` (per-node tree aggregation) are both wired today,
//! driven by `ConvertVerifierCircuit::build_verify_n_program_multi` in `lowering.rs`; `Compress` /
//! `Embed` are the planned siblings that reuse the same `Builder` and `verify_one`.
//!
//! For the wired Convert leaf, the generated program:
//!   1. Embeds each machine-fixed preprocessed commit (e.g. the byte table) as MemConst
//!      constants; app-identity preprocessed commits (the RISC-V program table) and the vk
//!      pre-hash are instead read from the witness stream, keeping the program app-independent
//!      (see `AirStructure::app_preprocessed` and the exe-identity anchor in `lowering.rs`).
//!   2. Drives the full Fiat-Shamir transcript via Poseidon2 instructions.
//!   3. Emits AssertZeroExt / FracFold / UnivariateFold / MleOpen chip instructions
//!      to check the algebraic identities in the proof.
//!
//! Assumptions:
//!   * need_rot handled per-AIR: when true, claim_rot is observed from the witness stream.
//!   * Each child AIR's presence and log_height come from the layout (`AirStructure::is_present`
//!     / `log_height`, read off the child proof's heights; with no proof, every AIR is present at
//!     the full stacked height) and are absorbed as constants, never witnessed.
//!   * Column openings are in air_id order.
//!
//! WHIR folding is performed via `binary_k_fold_circuit` (ExtAlu).

pub(super) use std::{
    borrow::{Borrow, BorrowMut},
    collections::HashMap,
};

pub(super) use p3_field::{Field, PrimeField32, TwoAdicField};

pub(super) use crate::{
    chips::chips::{exp_bits_len::NUM_BITS_MAX_PLUS_ONE, univariate_fold::MAX_COEFFS},
    compiler::{
        recursion::{
            instruction::{
                base_alu, commit_public_values, ext_alu, mem_block, HintInstr, Instruction,
            },
            ir::Block,
            program::RecursionProgram,
            types::{
                Address, AssertZeroExtInstr, BinaryFoldStepInstr, DigestSelectInstr,
                ExpBitsLenInstr, ExtDotProductInstr, FracFoldInstr, GkrSumcheckRoundInstr,
                HornerEvalInstr, LagrangeEvalD2Instr, MemAccessKind, MleOpenInstr, PackBlockInstr,
                Poseidon2PackedInstr, UnivariateFoldInstr, UnpackBlockInstr, WIDTH,
            },
        },
        word::Word,
    },
    emulator::{
        recursion::{
            emulator::{BaseAluOpcode, ExtAluOpcode},
            public_values::{
                RecursionPublicValues, NUM_PV_ELMS_TO_HASH, RECURSION_PUBLIC_VALUES_COL_MAP,
            },
        },
        riscv::public_values::PublicValues as RiscvPublicValues,
    },
    machine::septic::FieldSepticCurve,
    mle::machine::{
        air::GCS_DIGEST_LEN,
        exe::RISCV_VK_DIGEST_DOMAIN,
        vk_map::{MLE_VK_MERKLE_DEPTH, VK_MAP_LEAF_DOMAIN},
    },
    primitives::consts::{
        ADDR_NUM_LIMBS, DIGEST_SIZE, EXTENSION_DEGREE, MAX_NUM_PVS, RECURSION_NUM_PVS,
        RISCV_NUM_PVS,
    },
};
// Don't also import `WIDTH` from this module: it collides with the recursion-IR `WIDTH` imported
// above, a distinct constant equal to 16 only by coincidence.
pub(super) use pico_mle_core::config::koala_bear_poseidon2::RATE;

mod builder_field;
mod builder_ir;
mod builder_mle;
mod builder_transcript;
mod lowering;

/// Compute the Lagrange basis denominator inverse for interpolation at integer nodes {0,..,n-1}.
/// Returns `1 / prod_{j≠i}(i-j)` in the prime field `F`.
fn lagrange_basis_denom_inv<F: PrimeField32>(n: usize, i: usize) -> F {
    let p: u64 = F::ORDER_U64;
    let mut denom: u64 = 1;
    for j in 0..n {
        if j != i {
            let diff: i64 = (i as i64) - (j as i64);
            let diff_mod: u64 = if diff >= 0 {
                diff as u64 % p
            } else {
                p - ((-diff) as u64 % p)
            };
            denom = (denom as u128 * diff_mod as u128 % p as u128) as u64;
        }
    }
    // Inverse via Fermat's little theorem: denom^{P-2} mod P.
    let inv = mod_pow_u64(denom, p - 2, p);
    F::from_u32(inv as u32)
}

/// Modular exponentiation `base^exp mod modulus` (square-and-multiply), used by
/// `lagrange_basis_denom_inv` for the Fermat's-little-theorem field inverse.
fn mod_pow_u64(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result as u128 * base as u128 % modulus as u128) as u64;
        }
        exp >>= 1;
        base = (base as u128 * base as u128 % modulus as u128) as u64;
    }
    result
}

/// Canonical u32 of `2^{-k}` in the prime field `F` (i.e. `(2^{-1})^k mod P`).
fn inv_2_pow<F: PrimeField32>(k: u64) -> u32 {
    let p: u64 = F::ORDER_U64;
    let inv2 = p.div_ceil(2); // 2^{-1} = (P+1)/2 for odd prime P
    mod_pow_u64(inv2, k, p) as u32
}

// ─── Field-independent constraint evaluation DAG ─────────────────────────────

/// Variable entry type for field-independent evaluation DAG.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum EvalEntry {
    Preprocessed {
        offset: usize,
    },
    Main {
        part_index: usize,
        offset: usize,
    },
    /// Public value at the given index in the AIR's PV array.
    Public,
}

/// Node in the field-independent evaluation DAG.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum EvalNode {
    Variable { entry: EvalEntry, index: usize },
    IsFirstRow,
    IsLastRow,
    IsTransition,
    Constant(u32),
    Add(usize, usize),
    Sub(usize, usize),
    Neg(usize),
    Mul(usize, usize),
}

/// Interaction in the field-independent evaluation DAG.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct EvalInteraction {
    pub bus_index: u16,
    /// Node indices for message fields (in the shared node array).
    pub message: Vec<usize>,
    /// Node index for the count expression.
    pub count: usize,
    pub count_weight: u32,
}

/// Field-independent representation of an AIR's symbolic constraints.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct EvalDag {
    pub nodes: Vec<EvalNode>,
    pub constraint_idx: Vec<usize>,
    pub interactions: Vec<EvalInteraction>,
}

// ─── VK structure types (no SC generic) ──────────────────────────────────────

/// Per-AIR structural info needed to build the verifier program.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AirStructure {
    pub is_required: bool,
    /// Whether the AIR has a trace in the proof being verified.
    /// Required AIRs are always present; non-required AIRs default to absent.
    pub is_present: bool,
    /// The child trace's log2 height, baked into the verify program; `None` exactly when the AIR
    /// is absent.
    pub log_height: Option<usize>,
    pub has_preprocessed: bool,
    /// Preprocessed commit as [u32; 8] when has_preprocessed; embedded as constants in the verify
    /// program — EXCEPT when `app_preprocessed` (then the commit is witnessed, not baked).
    pub preprocessed_commit: Option<[u32; 8]>,
    /// This AIR's preprocessed commitment is *application identity* (the RISC-V program table): it
    /// is WITNESSED into the convert circuit (not baked as a constant) so the program stays
    /// app-independent. Only ever true in per-air mode (the RISCV machine). The witnessed value is
    /// still observed at the same transcript position and used as the same WHIR stacking root, so
    /// the transcript is unchanged; only the source (const → witness) differs.
    pub app_preprocessed: bool,
    pub num_cached_mains: usize,
    pub num_common_main_cols: usize,
    pub num_preprocessed_cols: usize,
    pub cached_main_widths: Vec<usize>,
    pub num_public_values: usize,
    pub num_interactions: usize,
    /// Whether this AIR has next-row constraints (max_rotation == 1).
    /// When true, column_openings contains interleaved [claim, claim_rot, ...] pairs.
    pub need_rot: bool,
    /// Whether any constraint or interaction expression references Entry::Public.
    pub uses_public_values: bool,
    /// Field-independent representation of this AIR's symbolic constraints.
    pub eval_dag: EvalDag,
}

/// Structural info extracted from a MultiStarkVerifyingKey; no SC generic.
///
/// Serializable so a root proof can be handed to another build for verification: the verifier
/// has to re-keygen the same node shape locally, and this is what pins it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RecursionVkLayout {
    pub vk_pre_hash: [u32; 8],
    /// Merged-preprocessed mode (recursion machines): the machine's single multi-matrix
    /// preprocessed commitment, observed once after `common_main_commit`. When set, per-air
    /// `preprocessed_commit` is `None` for every AIR (each prep AIR observes its `log_height`
    /// like a non-prep AIR), the merged commitment owns stacking commit index 1, and per-trace
    /// stacked commits carry cached mains only. `None` = per-air mode (the RISCV machine).
    pub merged_preprocessed_commit: Option<[u32; 8]>,
    pub l_skip: usize,
    /// Max trace level from params (used for stacking: always 2^(l_skip+n_stack) height).
    pub n_stack: usize,
    /// Actual max trace level from proof heights (or n_stack when no proof).
    /// Used for xi sampling loop and BC sumcheck rounds (matches verifier's n_max).
    pub n_max: usize,
    pub max_constraint_degree: usize,
    /// Actual n_logup from the proof being verified (or worst-case when no proof is available).
    pub n_logup: usize,
    pub logup_pow_bits: usize,
    pub mu_pow_bits: usize,
    pub folding_pow_bits: usize,
    pub query_phase_pow_bits: usize,
    pub k_whir: usize,
    pub num_whir_rounds: usize,
    pub log_final_poly_len: usize,
    pub num_queries_per_whir_round: Vec<usize>,
    pub per_air: Vec<AirStructure>,
    /// Maps trace_id → air_id for present AIRs, sorted by descending log_height then air_id.
    /// Matches the verifier's `trace_id_to_air_id` ordering.
    pub trace_ordering: Vec<usize>,
    /// log_height - l_skip per trace (in trace_ordering order). May be negative for short traces.
    pub n_per_trace: Vec<isize>,
    /// Stacking width per commit: [common_main, preproc[trace_0], cached[trace_0][0..], ...]
    /// Indexed in trace_id order (matches `trace_ordering`).
    pub stacking_widths: Vec<usize>,
    /// Per-commit stacking column layout: for each commit, for each sub-column,
    /// (n = log_height - l_skip, row_idx, stacked_col_idx, need_rot). Used for Deferred (stacking).
    pub stacking_col_layout: Vec<Vec<(isize, usize, usize, bool)>>,
    /// log2 of the WHIR RS domain size for round 0: l_skip + n_stack + log_blowup.
    pub log_rs_domain_size: usize,
}

/// Input to `build_verify_program`.
pub struct ConvertProgramInput {
    pub vk: RecursionVkLayout,
    /// Whitelist mode: when true the program witnesses `vk_root` into its public values
    /// (and combine nodes Merkle-verify each child's VK identity against it).
    pub vk_verification: bool,
}

/// Addresses of a proof's public values returned by `Builder::verify_one`.
struct ProofPvAddrs {
    /// Flat array of RECURSION_NUM_PVS memory addresses for the proof's public values.
    /// For a RISCV child these are in the RISCV `PublicValues` layout (zero-padded); for a
    /// recursion child they are already in the `RecursionPublicValues` layout.
    pv: Vec<u32>,
    /// Witnessed app-identity preprocessed commitment (the RISC-V program table), when present.
    /// Merkle-hard-bound in-circuit via `verify_one`'s stacking-root opening; the convert layer
    /// folds it into the `riscv_vk_digest` exe-identity digest, which the apex pins against the
    /// trusted `RiscvVmVk::digest()`. `None` for recursion children / no app table.
    app_prep_commit: Option<[u32; 8]>,
    /// Witnessed lean vk pre-hash (the transcript seed). Half of the child's whitelist
    /// identity: leaf = H(LEAF_DOMAIN ‖ vk_pre_hash ‖ merged_commit).
    vk_pre_hash: [u32; 8],
    /// Witnessed merged-preprocessed commitment (recursion children; the other identity half).
    /// `None` for per-air (RISC-V) children.
    merged_commit: Option<[u32; 8]>,
    /// A RISCV child's Global-air GCS public values (septic x[0..7] then y[7..14]); `None`
    /// for recursion children (their GCS already sits inside `pv` at recursion offsets).
    gcs_pv: Option<[u32; GCS_DIGEST_LEN]>,
    /// A RISCV child's riscv `PublicValues` copy, read from the Global air's pv tail (the
    /// Global air is present in EVERY chunk, so this is always available for RISCV children).
    /// `None` for recursion children.
    riscv_pv: Option<Vec<u32>>,
    /// Per-AIR public-value addresses (empty vec for airs whose pvs were not captured).
    /// Used by the RISCV→recursion PV translation to TIE the Global carrier copy to each
    /// present constrained pv air (Cpu / Ecall / MemInit / MemFinal) — see the carrier binding in
    /// `build_verify_n_program_multi`.
    per_air_pv: Vec<Vec<u32>>,
}

// ─── Public circuit types ─────────────────────────────────────────────────────

/// Verifies a single STARK proof inside the recursion machine.
pub struct ConvertVerifierCircuit;

// ─── Program builder ──────────────────────────────────────────────────────────

/// Read-multiplicity counter, keyed by the builder's own address counter.
///
/// Addresses come from `Builder::alloc`, a strictly sequential counter from 0, so the key space is
/// dense and a `HashMap<u32, u32>` under the default SipHash hasher was the wrong shape for it:
/// building one combine verify program does ~1 M `mark_read` bumps and `finish` does one lookup per
/// instruction (~570 k). `perf` put `mark_read` plus its hashing at ~8% of the combine preparer's
/// CPU — spent on the combine tree's serial critical path, where all four prover lanes are idle
/// waiting for it. (kb/host-patterns: `vec-indexed-by-sequential-key`.)
///
/// `get` keeps the `Option<&u32>` shape the `finish` backfill already uses, so the ~25 call sites
/// there are untouched; an address that was never read reads back as absent exactly as before
/// (out of range → `None`, in range but never bumped → `Some(&0)`; every caller does
/// `.copied().unwrap_or(0)`).
#[derive(Default)]
struct ReadCounts(Vec<u32>);

impl ReadCounts {
    fn bump(&mut self, addr: u32) {
        let i = addr as usize;
        if i >= self.0.len() {
            self.0.resize(i + 1, 0);
        }
        self.0[i] += 1;
    }

    fn get(&self, addr: &u32) -> Option<&u32> {
        self.0.get(*addr as usize)
    }
}

struct Builder<F> {
    next_addr: u32,
    instructions: Vec<Instruction<F>>,
    /// Tracks how many times each address is read (for mult backfill).
    read_counts: ReadCounts,
    /// Sponge lane addresses (fresh absorbed values; only lanes marked fresh are valid).
    sponge: [u32; WIDTH],
    /// Which lanes were overwritten by absorbs since the last permutation.
    lane_fresh: [bool; WIDTH],
    /// The 4 packed block addresses of the last permutation output.
    sponge_blocks: [u32; 4],
    /// Lazily unpacked lane addresses per output block.
    sponge_unpacked: [Option<[u32; 4]>; 4],
    absorb_idx: usize,
    sample_idx: usize,
    addr_zero: u32,
    addr_one: u32,
    addr_two: u32,
    /// Field inverse of 2 (= (P+1)/2), stored as EF constant.
    addr_inv2: u32,
    /// Addresses of Block([0,1,0,0]), Block([0,0,1,0]), Block([0,0,0,1])  (EF basis).
    ef_basis: [u32; 3],
    /// Address of every base-field constant written so far, keyed by its canonical u32 (see
    /// `const_f`).
    const_f_addrs: HashMap<u32, u32>,
}
