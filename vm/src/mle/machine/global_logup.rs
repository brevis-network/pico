//! The riscv machine's side of the global LogUp.
//!
//! Cross-chunk events (memory accesses that span chunks, syscalls handed to precompile chunks)
//! are checked in two phases. Each chunk's proof commits the chunk's event table on its own
//! ([`commit_global_table`]); the program's memory image is a committed table too
//! ([`ImageTable`]). Once every table is committed, the block's challenges are derived from the
//! commitments, and group proofs re-open the tables under them and hand back the fractional sum
//! of their rows ([`GlobalLogUp::prove`]). The events are consistent when the sums add up to
//! zero ([`GlobalLogUp::verify`]).
//!
//! The values all sides must agree on (heights, the chain over the commitments, the challenge
//! derivation, the real-row bound) are defined in `pico_mle_core::global_logup`.

use std::sync::Arc;

use p3_field::PrimeCharacteristicRing;
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use pico_mle_core::{
    air::symbolic::SymbolicExpressionNode,
    global_logup::{
        self, GroupMachines, COMMON_MAIN_FILL, COMMON_MAIN_WIDTH, MAX_GROUP_LEN, TABLE_WIDTH,
    },
    keygen::types::{MultiStarkVerifyingKey, MultiStarkVerifyingKeyInner},
    lookup::{LookupType, GLOBAL_KIND_VALUE_INDEX},
    proof::Proof,
    prover::{
        AirProvingContext, CommittedTraceData, DeviceDataTransporter, DeviceMultiStarkProvingKey,
        ProvingContext, TraceCommitter,
    },
    verifier::{verify_with_external_logup, VerifierError},
    StarkEngine, StarkProtocolConfig, SystemParams,
};
use pico_mle_cpu::{CpuBackend, CpuDevice, KoalaBearPoseidon2CpuEngine};
use pico_verifier::VmVk;

use super::riscv::{air_id, HostPb, Kb, Sc};
use crate::{
    chips::chips::riscv_global::columns::{NUM_GLOBAL_AUX_COLS, NUM_GLOBAL_COLS},
    compiler::{addr::encode_proof_addr_to_u32_limbs_48, riscv::program::Program},
    primitives::consts::LOCAL_MEMORY_DATAPAR,
};

pub use global_logup::{chain_iv, MAX_COUNT, MAX_GROUP_LEN as GROUP_LEN};

type Digest = <Sc as StarkProtocolConfig>::Digest;
type Ef = <Sc as StarkProtocolConfig>::EF;

/// The AIRs that send on the Global bus, in AIR id order: `(AIR id, sends per row, receives per
/// row)`.
///
/// The real-row bound counts a chunk's events from these numbers and the AIRs' heights, so the
/// table is part of the soundness argument, and [`assert_global_bus`] holds the machine's key
/// to it. A new or changed sender fails that assertion; before the table is updated its
/// multiplicities have to be checked boolean in its own AIR, since the count assumes one event
/// per `looking` per row at most.
pub const GLOBAL_SENDERS: [(usize, u64, u64); 5] = [
    (
        air_id::MEM_LOCAL,
        LOCAL_MEMORY_DATAPAR as u64,
        LOCAL_MEMORY_DATAPAR as u64,
    ),
    (air_id::SYSCALL_RISCV, 1, 0),
    (air_id::MEM_INIT, 1, 0),
    (air_id::MEM_FINAL, 0, 1),
    (air_id::SYSCALL_PRECOMPILE, 0, 1),
];

/// Whether the Global bus of a riscv verifying key is the one the global LogUp assumes.
///
/// - Exactly one AIR receives on it, the Global AIR, in one interaction: every event a sender
///   emits becomes a row of the chunk's table, and nothing else can absorb it.
/// - The senders are exactly [`GLOBAL_SENDERS`], each interaction with a literal direction.
pub fn check_global_bus(vk: &MultiStarkVerifyingKeyInner<Sc>) -> Result<(), String> {
    let mut receivers = Vec::new();
    let mut senders = Vec::new();
    for (air, air_vk) in vk.per_air.iter().enumerate() {
        let dag = &air_vk.symbolic_constraints;
        let constant = |node: usize| match dag.constraints.nodes.get(node) {
            Some(SymbolicExpressionNode::Constant(c)) => Some(*c),
            _ => None,
        };
        let (mut sends, mut receives) = (0u64, 0u64);
        for interaction in dag
            .interactions
            .iter()
            .filter(|interaction| interaction.kind == LookupType::Global)
        {
            if interaction.count_weight == 0 {
                receivers.push(air);
                continue;
            }
            if interaction.message.len() != GLOBAL_KIND_VALUE_INDEX + 1 {
                return Err(format!(
                    "air {air}: a Global-bus message of unexpected length"
                ));
            }
            let direction = (
                constant(interaction.message[GLOBAL_KIND_VALUE_INDEX - 2]),
                constant(interaction.message[GLOBAL_KIND_VALUE_INDEX - 1]),
            );
            if direction == (Some(Kb::ONE), Some(Kb::ZERO)) {
                sends += 1;
            } else if direction == (Some(Kb::ZERO), Some(Kb::ONE)) {
                receives += 1;
            } else {
                return Err(format!(
                    "air {air}: a Global-bus sender without a literal direction"
                ));
            }
        }
        if sends + receives > 0 {
            senders.push((air, sends, receives));
        }
    }
    if receivers != [air_id::GLOBAL] {
        return Err(format!(
            "the Global bus must have exactly one receiving interaction, in the Global AIR; \
             receiving AIRs: {receivers:?}"
        ));
    }
    if senders != GLOBAL_SENDERS {
        return Err(format!(
            "the Global-bus senders {senders:?} are not the audited table; check the new \
             sender's multiplicities are boolean, then update `GLOBAL_SENDERS`"
        ));
    }
    Ok(())
}

/// [`check_global_bus`] where the key is the caller's own: at keygen of the riscv machine.
///
/// # Panics
/// If the key differs.
pub fn assert_global_bus(vk: &MultiStarkVerifyingKeyInner<Sc>) {
    check_global_bus(vk).unwrap_or_else(|e| panic!("{e}"));
}

/// A chunk's share of the block's real-row bound, from the log heights its AIRs prove at
/// (`None` for an absent AIR). The convert program writes the same number for the chunk.
pub fn chunk_count(riscv: &SystemParams, log_height: impl Fn(usize) -> Option<usize>) -> u64 {
    global_logup::chunk_count(
        global_logup::global_log_height(riscv),
        GLOBAL_SENDERS
            .iter()
            .filter_map(|&(air, sends, receives)| log_height(air).map(|h| (sends, receives, h))),
    )
}

/// The real-row count of a block: the sum of its chunks' shares. The root of the recursion tree
/// carries the same sum.
pub fn block_count(riscv: &SystemParams, chunk_proofs: &[Proof<Sc>]) -> u64 {
    chunk_proofs
        .iter()
        .map(|chunk_proof| {
            chunk_count(riscv, |air| {
                chunk_proof
                    .trace_vdata
                    .get(air)
                    .and_then(|vdata| vdata.as_ref())
                    .map(|vdata| vdata.log_height)
            })
        })
        .sum()
}

/// The commitment of a chunk proof's Global event table, if the proof carries exactly one, at
/// `2^log_height` rows.
fn chunk_table_commit(chunk_proof: &Proof<Sc>, log_height: usize) -> Option<Digest> {
    match chunk_proof.trace_vdata.get(air_id::GLOBAL) {
        Some(Some(vdata))
            if vdata.log_height == log_height && vdata.cached_commitments.len() == 1 =>
        {
            Some(vdata.cached_commitments[0])
        }
        _ => None,
    }
}

/// The chain over the chunks' Global table commitments before each chunk and after the last:
/// `n + 1` values for `n` chunk proofs in chunk order, the first being the chain's initial
/// value. The convert leaf of the `i`-th proof takes the `i`-th value as its entry; the last
/// value is the root the block's challenges are derived from.
pub fn chain_values(
    riscv: &SystemParams,
    chunk_proofs: &[Proof<Sc>],
) -> Result<Vec<Digest>, GlobalLogUpError> {
    let mut chain = Chain::new(riscv);
    for (chunk, chunk_proof) in chunk_proofs.iter().enumerate() {
        chain
            .push_proof(chunk_proof)
            .ok_or(GlobalLogUpError::ChunkTable {
                chunk,
                expected: chain.log_height,
            })?;
    }
    Ok(chain.values)
}

/// The chain over a block's Global table commitments, grown one chunk at a time: for a prover
/// that learns the commitments as its chunks are proved. [`chain_values`] is the same chain over
/// a block's finished proofs.
pub struct Chain {
    log_height: usize,
    values: Vec<Digest>,
}

impl Chain {
    /// The chain before any chunk, for the riscv machine at `riscv`.
    pub fn new(riscv: &SystemParams) -> Self {
        Self {
            log_height: global_logup::global_log_height(riscv),
            values: vec![global_logup::chain_iv()],
        }
    }

    /// The values so far: the `i`-th is the chain before chunk `i + 1`, the last the value
    /// after every chunk pushed.
    pub fn values(&self) -> &[Digest] {
        &self.values
    }

    /// The commitment the next chunk's proof carries, or `None` if it has no Global table at
    /// this machine's height.
    pub fn commit_of(&self, chunk_proof: &Proof<Sc>) -> Option<Digest> {
        chunk_table_commit(chunk_proof, self.log_height)
    }

    /// Step the chain over the next chunk's commitment.
    pub fn push(&mut self, commit: &Digest) {
        let index = u32::try_from(self.values.len()).expect("a block has fewer than 2^32 chunks");
        let prev = *self.values.last().expect("the chain has its initial value");
        self.values.push(global_logup::chain_step(
            &prev,
            index,
            self.log_height,
            commit,
        ));
    }

    /// [`Self::push`] with the commitment of the next chunk's proof; `None`, and no step, if the
    /// proof carries none.
    pub fn push_proof(&mut self, chunk_proof: &Proof<Sc>) -> Option<()> {
        let commit = self.commit_of(chunk_proof)?;
        self.push(&commit);
        Some(())
    }
}

/// Commit `table` on its own under the riscv machine's parameters.
fn commit_table(table: RowMajorMatrix<Kb>, riscv: &SystemParams) -> CommittedTraceData<HostPb> {
    let device = CpuDevice::new(Sc::default_from_params(riscv.clone()));
    let (commitment, data) = device
        .commit(&[&table])
        .expect("a table no taller than the stacked height commits");
    CommittedTraceData {
        commitment,
        trace: table,
        data: Arc::new(data),
    }
}

/// `matrix` with zero rows appended up to `2^log_height` rows.
fn padded(matrix: &RowMajorMatrix<Kb>, log_height: usize) -> RowMajorMatrix<Kb> {
    let width = matrix.width();
    assert!(
        matrix.height() <= 1 << log_height,
        "{} rows do not fit a table of 2^{log_height}",
        matrix.height()
    );
    let mut values = matrix.values.clone();
    values.resize(width << log_height, Kb::ZERO);
    RowMajorMatrix::new(values, width)
}

/// The commitment of a program's memory image table and the height tier it was committed at:
/// what a verifier trusts about the image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageCommitment {
    pub commit: Digest,
    pub log_height: usize,
}

impl ImageCommitment {
    /// The program's vk digest under the global LogUp, over the program-table commitment, the
    /// entry pc and this image.
    pub fn vm_vk_digest(&self, program_commit: &Digest, pc_start: &[Kb; 3]) -> Digest {
        VmVk {
            program_commit: *program_commit,
            pc_start: *pc_start,
            image_commit: self.commit,
            image_log_height: Kb::from_usize(self.log_height),
        }
        .digest()
    }
}

/// A program whose memory image is larger than the largest image table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "the program's memory image has {words} words; the largest image table holds 2^{max_log_height}"
)]
pub struct ImageTooLarge {
    pub words: usize,
    pub max_log_height: usize,
}

/// The program's memory image as a table of the global LogUp.
///
/// One row per image word, in ascending address order: the message MemoryInitialize would send
/// for the word at chunk 0, clk 0, as a send. Zero rows follow, up to the smallest height tier
/// that holds the image. The form is canonical, so every party computes the same commitment for
/// a program; the tier is part of the program's identity next to it.
pub struct ImageTable {
    log_height: usize,
    committed: CommittedTraceData<HostPb>,
}

impl ImageTable {
    pub fn new(program: &Program, riscv: &SystemParams) -> Result<Self, ImageTooLarge> {
        let words = program.memory_image.len();
        let log_height = global_logup::image_log_height(riscv, words).ok_or(ImageTooLarge {
            words,
            max_log_height: *global_logup::image_log_heights(riscv).end(),
        })?;
        let mut values = vec![Kb::ZERO; TABLE_WIDTH << log_height];
        for (row, (&addr, &word)) in values
            .as_chunks_mut::<TABLE_WIDTH>()
            .0
            .iter_mut()
            .zip(program.memory_image.iter())
        {
            let addr = encode_proof_addr_to_u32_limbs_48(addr, "program memory address");
            let limb = |i: u32| ((word >> (16 * i)) & 0xFFFF) as u32;
            // message[0] (chunk) and message[1] (clk) are zero.
            row[2] = Kb::from_u32(addr[0]);
            row[3] = Kb::from_u32(addr[1]);
            row[4] = Kb::from_u32(addr[2]);
            row[5] = Kb::from_u32(limb(0) + ((limb(2) & 0xFF) << 16));
            row[6] = Kb::from_u32(limb(1) + ((limb(2) >> 8) << 16));
            row[7] = Kb::from_u32(limb(3));
            row[8] = Kb::from_u8(LookupType::Memory as u8);
            row[global_logup::MULTIPLICITY_COL] = Kb::ONE;
        }
        let committed = commit_table(RowMajorMatrix::new(values, TABLE_WIDTH), riscv);
        Ok(Self {
            log_height,
            committed,
        })
    }

    pub fn commitment(&self) -> ImageCommitment {
        ImageCommitment {
            commit: self.committed.commitment,
            log_height: self.log_height,
        }
    }

    /// Negative tests only: the same stacked column read as a table of the next tier, or `None`
    /// when that reading commits differently (the table then spans more than one stacked
    /// column). The reading puts the kind and multiplicity columns on zeros, so a group proof
    /// over it sums to nothing under the very same commitment: what a verifier that did not
    /// hold the program to its tier would accept as the program's image.
    #[doc(hidden)]
    pub fn read_one_tier_up(&self, riscv: &SystemParams) -> Option<Self> {
        let rows = 1usize << self.log_height;
        let table = &self.committed.trace;
        // Ten columns of `rows` cells, laid end to end, are five columns of `2 * rows` cells.
        let mut reread = vec![Kb::ZERO; TABLE_WIDTH * 2 * rows];
        for r in 0..2 * rows {
            for col in 0..TABLE_WIDTH / 2 {
                reread[r * TABLE_WIDTH + col] =
                    table.values[(r % rows) * TABLE_WIDTH + 2 * col + r / rows];
            }
        }
        let committed = commit_table(RowMajorMatrix::new(reread, TABLE_WIDTH), riscv);
        (committed.commitment == self.committed.commitment).then_some(Self {
            log_height: self.log_height + 1,
            committed,
        })
    }
}

/// A chunk's Global event table as the prover holds it between the chunk's proof and the group
/// proof that re-opens it: the commitment, and the rows without the padding up to the fixed
/// height.
pub struct ChunkTable {
    pub commit: Digest,
    rows: RowMajorMatrix<Kb>,
}

impl ChunkTable {
    /// A table committed elsewhere than [`commit_global_table`]: on the device, by the GPU
    /// prover. `rows` are the table's rows from the top, any padding after them left out.
    #[cfg(feature = "cuda")]
    pub(crate) fn new(commit: Digest, rows: RowMajorMatrix<Kb>) -> Self {
        assert_eq!(
            rows.width(),
            TABLE_WIDTH,
            "a Global table is {TABLE_WIDTH} wide"
        );
        Self { commit, rows }
    }
}

/// Whether the Global AIR of `ctx` already has its table committed.
pub fn global_table_is_committed(ctx: &ProvingContext<HostPb>) -> bool {
    global_entry(ctx).1.cached_mains.len() == 1
}

fn global_entry(ctx: &ProvingContext<HostPb>) -> &(usize, AirProvingContext<HostPb>) {
    ctx.per_trace
        .iter()
        .find(|(air, _)| *air == air_id::GLOBAL)
        .expect("every riscv chunk has the Global AIR")
}

/// Complete a host proving context for a prove.
///
/// Trace generation leaves the Global chip's rows as one matrix at their natural height. The
/// Global AIR proves at the machine's fixed height with the event table in a partition of its
/// own, so this pads the rows to that height, splits the table off, and commits it. The same
/// commitment is what the chunk's group proof opens later; the returned [`ChunkTable`] is what
/// the group prover needs for it.
///
/// # Panics
/// If the chunk has more events than the fixed height holds: the emulator cuts chunks so that it
/// does not.
pub fn commit_global_table(
    mut ctx: ProvingContext<HostPb>,
    riscv: &SystemParams,
) -> (ProvingContext<HostPb>, ChunkTable) {
    let log_height = global_logup::global_log_height(riscv);
    let entry = ctx
        .per_trace
        .iter_mut()
        .find(|(air, _)| *air == air_id::GLOBAL)
        .expect("every riscv chunk has the Global AIR");
    let raw = &entry.1.common_main;
    assert!(
        entry.1.cached_mains.is_empty() && raw.width() == NUM_GLOBAL_COLS,
        "the Global table of this context is already committed"
    );
    // TODO(global-table-height): the emulator cuts records for the table of the default stacked
    // height (2^22 events: the chunk splitter's cap, the precompile blocks and the memory
    // buckets of `emulator::riscv::record`), so below that height a record can hold more
    // events than this table has rows, and is refused here; a memory record's size does not
    // follow the chunk size. One table of 2^22 rows is a first implementation: once the
    // table's shape is settled, cut the records for it at every stacked height.
    assert!(
        raw.height() <= 1 << log_height,
        "the chunk has more cross-chunk events ({} rows) than a Global table of 2^{log_height} \
         holds; below the default stacked height the records are still cut for the default's \
         table, and a higher stacked height holds this one",
        raw.height()
    );
    let (mut table, mut aux) = (
        Vec::with_capacity(raw.height() * TABLE_WIDTH),
        Vec::with_capacity(NUM_GLOBAL_AUX_COLS << log_height),
    );
    for row in raw.values.as_chunks::<NUM_GLOBAL_COLS>().0 {
        table.extend_from_slice(&row[..TABLE_WIDTH]);
        aux.extend_from_slice(&row[TABLE_WIDTH..]);
    }
    aux.resize(NUM_GLOBAL_AUX_COLS << log_height, Kb::ZERO);
    let rows = RowMajorMatrix::new(table, TABLE_WIDTH);
    let committed = commit_table(padded(&rows, log_height), riscv);
    let commit = committed.commitment;
    let public_values = std::mem::take(&mut entry.1.public_values);
    entry.1 = AirProvingContext::new(
        vec![committed],
        RowMajorMatrix::new(aux, NUM_GLOBAL_AUX_COLS),
        public_values,
    );
    (ctx, ChunkTable { commit, rows })
}

/// What a group prover says when a kept table commits to another root than its chunk's proof
/// opened.
const STALE_TABLE: &str = "a kept Global table no longer commits to what its chunk proof opened";

/// The group machines' prover on a GPU: the riscv machine's engine type under the group
/// machines' parameters.
#[cfg(feature = "cuda")]
struct DeviceGroupProver {
    engine: crate::mle::machine::riscv::Engine,
    /// `d_pks[s - 1]` is the device key of the machine for `s` tables.
    d_pks: Vec<DeviceMultiStarkProvingKey<crate::mle::machine::riscv::Pb>>,
}

#[cfg(feature = "cuda")]
impl DeviceGroupProver {
    fn new(machines: &GroupMachines) -> Self {
        let mut engine: crate::mle::machine::riscv::Engine =
            StarkEngine::new(machines.config().params().clone());
        // As for the riscv machine: the codeword of a 2^22 table is recomputed, not kept.
        engine.device_mut().set_cache_rs_code_matrix(false);
        let d_pks = (1..=MAX_GROUP_LEN)
            .map(|tables| {
                let pk = machines.pk(tables).expect("a key per group size");
                let d_pk = engine.device().transport_pk_to_device(pk);
                cuda_mle::warmup_jit_kernels(&d_pk);
                d_pk
            })
            .collect();
        Self { engine, d_pks }
    }

    /// `GlobalLogUp::prove_group` on the device. Each table is given as its rows from the top
    /// and the log height the group machine reads it at: the rows are uploaded, the zero rows
    /// below them are filled in on the card, and the table is committed there.
    fn prove_group(
        &self,
        tables: Vec<(&RowMajorMatrix<Kb>, usize, Option<Digest>)>,
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        use crate::mle::machine::riscv::Pb;
        use cuda_mle::{
            base::DeviceMatrix, data_transporter::transport_matrix_h2d_row_major,
            runtime::stream::current_stream_sync,
        };
        use pico_mle_core::prover::TraceCommitter;

        // The common main is one column of zeros.
        const _: () = assert!(COMMON_MAIN_FILL == 0);
        let d_pk = &self.d_pks[tables.len() - 1];
        let per_trace = tables
            .into_iter()
            .enumerate()
            .map(|(air, (rows, log_height, commit))| {
                let (height, real) = (1usize << log_height, rows.height());
                assert!(
                    real <= height,
                    "{real} rows do not fit a table of 2^{log_height}"
                );
                let upload = || {
                    transport_matrix_h2d_row_major(rows)
                        .map_err(|e| format!("uploading a Global table failed: {e:?}"))
                };
                let trace = if real == height {
                    upload()?
                } else {
                    let trace = DeviceMatrix::<Kb>::with_capacity(height, rows.width());
                    if real == 0 {
                        trace
                            .buffer()
                            .fill_zero()
                            .map_err(|e| format!("zeroing a Global table failed: {e:?}"))?;
                    } else {
                        let top = upload()?;
                        // SAFETY: `top` holds `width` columns of `real` elements and `trace`
                        // has room for as many of `height`.
                        unsafe {
                            cuda_mle::batch_expand_pad_any(
                                trace.buffer().as_mut_ptr(),
                                top.buffer().as_ptr(),
                                rows.width() as u32,
                                height as u32,
                                real as u32,
                            )
                        }
                        .map_err(|e| format!("padding a Global table failed: {e:?}"))?;
                        // The padding reads `top`, which goes back to the pool below.
                        current_stream_sync()
                            .map_err(|e| format!("padding a Global table failed: {e:?}"))?;
                    }
                    trace
                };
                let (commitment, data) =
                    TraceCommitter::<Pb>::commit(self.engine.device(), &[&trace])
                        .map_err(|e| format!("committing a Global table failed: {e:?}"))?;
                assert!(
                    commit.is_none_or(|commit| commit == commitment),
                    "{STALE_TABLE}"
                );
                let common_main = DeviceMatrix::<Kb>::with_capacity(height, COMMON_MAIN_WIDTH);
                common_main
                    .buffer()
                    .fill_zero()
                    .map_err(|e| format!("zeroing a group proof's common main failed: {e:?}"))?;
                let committed = CommittedTraceData {
                    commitment,
                    trace,
                    data: Arc::new(data),
                };
                Ok((
                    air,
                    AirProvingContext::new(vec![committed], common_main, vec![]),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let ctx = ProvingContext::new(per_trace).with_external_logup_challenges(alpha, beta);
        cuda_mle::set_prove_phase("global_logup_group");
        self.engine
            .prove(d_pk, ctx)
            .map_err(|e| format!("global LogUp group proof failed: {e:?}"))
    }
}

/// The second phase of a block's proof: what the group proofs add to the chunk proofs.
#[derive(Clone)]
pub struct GlobalLogUpProof {
    /// The proof-of-work witness behind the block's challenges.
    pub pow_witness: Kb,
    /// The group proof over the program's memory image table.
    pub image_proof: Proof<Sc>,
    /// The group proofs over the chunks' tables, in chunk order: each covers the chunks after
    /// the previous one's, as many as it has tables.
    pub group_proofs: Vec<Proof<Sc>>,
}

/// Whether the sums a block's group proofs state, the image group's among them, add up to zero
/// over a non-zero denominator.
///
/// The prover's own early look at its block, before it spends the recursion on the proofs:
/// the sums are read as stated, nothing is verified. A block whose chunks disagree on a
/// cross-chunk event fails here.
pub fn stated_sums_balance<'a>(group_proofs: impl IntoIterator<Item = &'a Proof<Sc>>) -> bool {
    let sum = group_proofs
        .into_iter()
        .map(|proof| {
            (
                proof.gkr_proof.p0_claim.unwrap_or(Ef::ZERO),
                proof.gkr_proof.q0_claim,
            )
        })
        .fold((Ef::ZERO, Ef::ONE), global_logup::add_fractions);
    sum.0 == Ef::ZERO && sum.1 != Ef::ZERO
}

/// Why a block's global LogUp does not verify.
#[derive(Debug, thiserror::Error)]
pub enum GlobalLogUpError {
    #[error("the bundle holds no chunk proof")]
    NoChunks,
    #[error("chunk {chunk}: the proof does not carry one Global table commitment at 2^{expected}")]
    ChunkTable { chunk: usize, expected: usize },
    #[error("the proof-of-work witness of the global LogUp challenges is invalid")]
    ProofOfWork,
    #[error("group proof {group} holds {tables} tables; a group holds 1 to {MAX_GROUP_LEN}")]
    GroupSize { group: usize, tables: usize },
    #[error("the group proofs cover {covered} chunks of {chunks}")]
    Coverage { covered: usize, chunks: usize },
    #[error("group proof {group}, table {table}: not the committed Global table of chunk {chunk}")]
    GroupTable {
        group: usize,
        table: usize,
        chunk: usize,
    },
    #[error("group proof {group}: {source}")]
    Group {
        group: usize,
        source: VerifierError<Ef>,
    },
    #[error("the image group proof does not open the program's memory image table")]
    ImageTable,
    #[error("the image group proof: {0}")]
    Image(VerifierError<Ef>),
    #[error("the global LogUp does not balance: the chunks' cross-chunk events are inconsistent")]
    Unbalanced,
    #[error("the chunks' real-row count is {count}; a block may reach {max}")]
    TooManyRows { count: u64, max: u64 },
}

/// The group machines of one riscv operating point, ready to prove and verify on the CPU.
pub struct GlobalLogUp {
    riscv: SystemParams,
    machines: GroupMachines,
    engine: KoalaBearPoseidon2CpuEngine,
    /// `d_pks[s - 1]` is the device key of the machine for `s` tables.
    d_pks: Vec<DeviceMultiStarkProvingKey<CpuBackend<Sc>>>,
    /// The GPU prover of the group proofs, once [`Self::use_device`] has built it. Verifying
    /// stays on the host.
    #[cfg(feature = "cuda")]
    device: Option<DeviceGroupProver>,
}

impl GlobalLogUp {
    /// Keygen the group machines for the riscv machine at `riscv`.
    pub fn new(riscv: &SystemParams) -> Self {
        let machines = GroupMachines::new(riscv);
        let engine: KoalaBearPoseidon2CpuEngine =
            StarkEngine::new(machines.config().params().clone());
        let d_pks = (1..=MAX_GROUP_LEN)
            .map(|tables| {
                let pk = machines.pk(tables).expect("a key per group size");
                engine.device().transport_pk_to_device(pk)
            })
            .collect();
        Self {
            riscv: riscv.clone(),
            machines,
            engine,
            d_pks,
            #[cfg(feature = "cuda")]
            device: None,
        }
    }

    /// The group machines' keys through the production keygen's gate
    /// (`GroupMachines::admit_production`).
    pub fn admit_production(
        &self,
        backend: &str,
    ) -> Result<(), pico_mle_core::config::soundness::UnderBudgetError> {
        self.machines.admit_production(backend)
    }

    /// Prove the group proofs on the calling thread's card from here on: the group keys go to
    /// the device and their kernels are compiled now. Call it where the riscv machine's own
    /// keys are set up, before the prover's threads start (`RiscvMachine::from_airs` says why).
    #[cfg(feature = "cuda")]
    pub fn use_device(&mut self) {
        self.device = Some(DeviceGroupProver::new(&self.machines));
    }

    /// Prove the second phase of a block: derive the challenges from the chunks' table
    /// commitments, then prove the image group and the chunk groups under them.
    ///
    /// `tables` are the chunks' tables in chunk order, complete: the chain the challenges come
    /// from runs over exactly these commitments.
    pub fn prove(
        &self,
        vm_vk_digest: &Digest,
        image: &ImageTable,
        tables: &[ChunkTable],
    ) -> Result<GlobalLogUpProof, String> {
        self.prove_grouped(vm_vk_digest, image, tables, MAX_GROUP_LEN)
    }

    /// The block's challenges, with the proof-of-work witness behind them: derived from the
    /// chain over the commitments of `tables`, the block's tables in chunk order, complete.
    /// With [`Self::prove_image_of`] and [`Self::prove_group_of`], [`Self::prove`] in pieces: for
    /// a caller that proves the groups on several machines at once.
    pub fn challenges(&self, vm_vk_digest: &Digest, tables: &[ChunkTable]) -> (Kb, Ef, Ef) {
        let log_height = global_logup::global_log_height(&self.riscv);
        let root = global_logup::chain_root(log_height, tables.iter().map(|table| table.commit));
        self.challenges_at(vm_vk_digest, &root)
    }

    /// [`Self::challenges`] from the chain's root, its value after the block's last chunk
    /// ([`Chain`]): for a prover that holds the block's chain and only some of its tables.
    /// The witness is the least valid one, so every machine of a block derives the same.
    pub fn challenges_at(&self, vm_vk_digest: &Digest, chain_root: &Digest) -> (Kb, Ef, Ef) {
        global_logup::derive_challenges(
            &self.machines.params_digest(),
            vm_vk_digest,
            chain_root,
            self.riscv.logup.pow_bits,
        )
    }

    /// The image group's proof under the block's challenges.
    pub fn prove_image_of(
        &self,
        image: &ImageTable,
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        self.prove_image(image, alpha, beta)
    }

    /// One chunk group's proof under the block's challenges: `tables` are consecutive chunks'
    /// tables, at most a group's worth. Each is committed again and has to give the commitment
    /// its chunk's proof opened.
    pub fn prove_group_of(
        &self,
        tables: &[ChunkTable],
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        if self.machines.pk(tables.len()).is_none() {
            return Err(format!(
                "a group holds 1 to {MAX_GROUP_LEN} tables, not {}",
                tables.len()
            ));
        }
        let log_height = global_logup::global_log_height(&self.riscv);
        // On the device only a table's own rows cross to the card, which pads them.
        #[cfg(feature = "cuda")]
        if let Some(device) = &self.device {
            let tables = tables
                .iter()
                .map(|table| (&table.rows, log_height, Some(table.commit)))
                .collect();
            return device.prove_group(tables, alpha, beta);
        }
        let tables = tables
            .iter()
            .map(|table| (padded(&table.rows, log_height), Some(table.commit)))
            .collect();
        self.prove_group(tables, alpha, beta)
    }

    /// [`Self::prove`] with `group_len` tables to a group instead of as many as a group holds.
    /// Any grouping that covers the chunks in order verifies; tests take small groups to get
    /// several of them out of a short block.
    #[doc(hidden)]
    pub fn prove_grouped(
        &self,
        vm_vk_digest: &Digest,
        image: &ImageTable,
        tables: &[ChunkTable],
        group_len: usize,
    ) -> Result<GlobalLogUpProof, String> {
        assert!((1..=MAX_GROUP_LEN).contains(&group_len));
        let (pow_witness, alpha, beta) = self.challenges(vm_vk_digest, tables);
        let image_proof = self.prove_image(image, alpha, beta)?;
        let group_proofs = tables
            .chunks(group_len)
            .map(|group| self.prove_group_of(group, alpha, beta))
            .collect::<Result<_, _>>()?;
        Ok(GlobalLogUpProof {
            pow_witness,
            image_proof,
            group_proofs,
        })
    }

    /// A group proof over `tables` under challenges of the caller's choosing. The proof is a
    /// valid group proof; a negative test puts it where the block's challenges are expected.
    #[doc(hidden)]
    pub fn prove_group_under(
        &self,
        tables: &[&ChunkTable],
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        let log_height = global_logup::global_log_height(&self.riscv);
        let tables = tables
            .iter()
            .map(|table| (padded(&table.rows, log_height), None))
            .collect();
        self.prove_group(tables, alpha, beta)
    }

    /// [`Self::prove_group_under`] for the image group.
    #[doc(hidden)]
    pub fn prove_image_under(
        &self,
        image: &ImageTable,
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        self.prove_image(image, alpha, beta)
    }

    /// The group proof over the image table, whose commitment data the host holds from setup.
    fn prove_image(&self, image: &ImageTable, alpha: Ef, beta: Ef) -> Result<Proof<Sc>, String> {
        #[cfg(feature = "cuda")]
        if let Some(device) = &self.device {
            let trace = &image.committed.trace;
            let table = (
                trace,
                p3_util::log2_strict_usize(trace.height()),
                Some(image.committed.commitment),
            );
            return device.prove_group(vec![table], alpha, beta);
        }
        self.prove_committed(vec![image.committed.clone()], alpha, beta)
    }

    /// One group proof over `tables`: each is a table's rows at the height the group machine
    /// reads it at, padding included, with the commitment its chunk proof opened it under. The
    /// table is committed again here, and has to give that commitment (`None` takes whatever
    /// it gives).
    fn prove_group(
        &self,
        tables: Vec<(RowMajorMatrix<Kb>, Option<Digest>)>,
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        #[cfg(feature = "cuda")]
        if let Some(device) = &self.device {
            let tables = tables
                .iter()
                .map(|(rows, commit)| (rows, p3_util::log2_strict_usize(rows.height()), *commit))
                .collect();
            return device.prove_group(tables, alpha, beta);
        }
        let committed = tables
            .into_iter()
            .map(|(rows, commit)| {
                let committed = commit_table(rows, &self.riscv);
                assert!(
                    commit.is_none_or(|commit| commit == committed.commitment),
                    "{STALE_TABLE}"
                );
                committed
            })
            .collect();
        self.prove_committed(committed, alpha, beta)
    }

    fn prove_committed(
        &self,
        tables: Vec<CommittedTraceData<HostPb>>,
        alpha: Ef,
        beta: Ef,
    ) -> Result<Proof<Sc>, String> {
        let d_pk = &self.d_pks[tables.len() - 1];
        let per_trace = tables
            .into_iter()
            .map(|table| {
                let common_main = RowMajorMatrix::new(
                    vec![Kb::from_u32(COMMON_MAIN_FILL); table.trace.height() * COMMON_MAIN_WIDTH],
                    COMMON_MAIN_WIDTH,
                );
                AirProvingContext::new(vec![table], common_main, vec![])
            })
            .enumerate()
            .collect();
        let ctx = ProvingContext::new(per_trace).with_external_logup_challenges(alpha, beta);
        self.engine
            .prove(d_pk, ctx)
            .map_err(|e| format!("global LogUp group proof failed: {e:?}"))
    }

    /// Verify the second phase of a block against its chunk proofs, which the caller has
    /// verified under `riscv_vk`.
    ///
    /// `vm_vk_digest` and `image` are trusted: they identify the program. Checked here:
    /// - there is a chunk proof, and every chunk proof carries one Global table commitment at
    ///   the fixed height;
    /// - the challenges are the ones derived from the chain over those commitments, behind a
    ///   valid proof of work;
    /// - each group proof verifies under this verifier's own key for its size and the block's
    ///   challenges, and opens, at the fixed height and in order, the commitments of the chunks
    ///   it covers; the groups cover every chunk once;
    /// - the image proof likewise opens the trusted image commitment at its tier;
    /// - the fractional sums add up to zero over a non-zero denominator;
    /// - the chunks' real-row count is within the limit.
    pub fn verify(
        &self,
        chunk_proofs: &[Proof<Sc>],
        proof: &GlobalLogUpProof,
        vm_vk_digest: &Digest,
        image: &ImageCommitment,
    ) -> Result<(), GlobalLogUpError> {
        self.verify_within(
            chunk_proofs,
            proof,
            vm_vk_digest,
            image,
            global_logup::MAX_COUNT,
        )
    }

    /// [`Self::verify`] with the real-row limit as a parameter. The limit is `MAX_COUNT`; a
    /// smaller one is still sound, and lets a test put it below a block's count.
    fn verify_within(
        &self,
        chunk_proofs: &[Proof<Sc>],
        proof: &GlobalLogUpProof,
        vm_vk_digest: &Digest,
        image: &ImageCommitment,
        max_count: u64,
    ) -> Result<(), GlobalLogUpError> {
        if chunk_proofs.is_empty() {
            return Err(GlobalLogUpError::NoChunks);
        }
        let log_height = global_logup::global_log_height(&self.riscv);
        let commits = chunk_proofs
            .iter()
            .enumerate()
            .map(|(chunk, chunk_proof)| {
                chunk_table_commit(chunk_proof, log_height).ok_or(GlobalLogUpError::ChunkTable {
                    chunk,
                    expected: log_height,
                })
            })
            .collect::<Result<Vec<Digest>, _>>()?;

        let root = global_logup::chain_root(log_height, commits.iter().copied());
        let (alpha, beta) = global_logup::check_challenges(
            &self.machines.params_digest(),
            vm_vk_digest,
            &root,
            self.riscv.logup.pow_bits,
            proof.pow_witness,
        )
        .ok_or(GlobalLogUpError::ProofOfWork)?;

        // Structure first: sizes and coverage, before any proof is verified.
        let mut covered = 0;
        for (group, group_proof) in proof.group_proofs.iter().enumerate() {
            let tables = group_proof.trace_vdata.len();
            if self.machines.vk(tables).is_none() {
                return Err(GlobalLogUpError::GroupSize { group, tables });
            }
            covered += tables;
        }
        if covered != commits.len() {
            return Err(GlobalLogUpError::Coverage {
                covered,
                chunks: commits.len(),
            });
        }

        let image_sum = self
            .verify_group(&proof.image_proof, alpha, beta)
            .map_err(GlobalLogUpError::Image)?;
        if !opens(&proof.image_proof, 0, image.log_height, &image.commit)
            || proof.image_proof.trace_vdata.len() != 1
        {
            return Err(GlobalLogUpError::ImageTable);
        }
        let mut sum = image_sum;
        let mut chunk = 0;
        for (group, group_proof) in proof.group_proofs.iter().enumerate() {
            let group_sum = self
                .verify_group(group_proof, alpha, beta)
                .map_err(|source| GlobalLogUpError::Group { group, source })?;
            for table in 0..group_proof.trace_vdata.len() {
                if !opens(group_proof, table, log_height, &commits[chunk]) {
                    return Err(GlobalLogUpError::GroupTable {
                        group,
                        table,
                        chunk,
                    });
                }
                chunk += 1;
            }
            sum = global_logup::add_fractions(sum, group_sum);
        }
        if sum.0 != Ef::ZERO || sum.1 == Ef::ZERO {
            return Err(GlobalLogUpError::Unbalanced);
        }

        let count = block_count(&self.riscv, chunk_proofs);
        if count > max_count {
            return Err(GlobalLogUpError::TooManyRows {
                count,
                max: max_count,
            });
        }
        Ok(())
    }

    /// Verify one group proof under this verifier's key for its size, giving its sum. The size
    /// is the proof's AIR count; the caller has checked it is one a key exists for.
    fn verify_group(
        &self,
        proof: &Proof<Sc>,
        alpha: Ef,
        beta: Ef,
    ) -> Result<(Ef, Ef), VerifierError<Ef>> {
        let vk: &MultiStarkVerifyingKey<Sc> = self
            .machines
            .vk(proof.trace_vdata.len())
            .ok_or(VerifierError::EmptyTraces)?;
        verify_with_external_logup(
            self.engine.config(),
            vk,
            proof,
            &mut self.engine.initial_transcript(),
            alpha,
            beta,
        )
    }
}

/// Whether `proof`'s AIR `table` opens exactly `commit`, as a table of `2^log_height` rows. The
/// verifier takes heights from the proof, so the height is checked here: read at another height,
/// a commitment gives other columns.
fn opens(proof: &Proof<Sc>, table: usize, log_height: usize, commit: &Digest) -> bool {
    matches!(
        proof.trace_vdata.get(table),
        Some(Some(vdata))
            if vdata.log_height == log_height && vdata.cached_commitments == [*commit]
    )
}

#[cfg(all(test, not(feature = "cuda")))]
mod tests {
    use std::{borrow::BorrowMut, sync::OnceLock};

    use p3_air::{Air, RowWindow};
    use pico_mle_core::prover::DeviceMultiStarkProvingKey;

    use super::*;
    use crate::{
        chips::chips::{
            riscv_global::columns::GlobalCols,
            riscv_memory::{
                event::MemoryInitializeFinalizeEvent,
                initialize_finalize::{
                    columns::{MemoryInitializeFinalizeCols, NUM_MEMORY_INITIALIZE_FINALIZE_COLS},
                    MemoryChipType, MemoryInitializeFinalizeChip,
                },
                local::{
                    columns::{MemoryLocalCols, NUM_MEMORY_LOCAL_INIT_COLS},
                    MemoryLocalChip,
                },
            },
            syscall::{columns::SyscallCols, SyscallChip, NUM_SYSCALL_COLS},
        },
        compiler::riscv::{
            compiler::{Compiler, SourceType},
            opcode::ByteOpcode,
        },
        configs::stark_config::KoalaBearPoseidon2,
        emulator::{riscv::record::EmulationRecord, stdin::EmulatorStdin},
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::debug_folder::{DebugConstraintFailure, DebugConstraintFolder},
        mle::machine::riscv::{
            self, build_ctx, mle_riscv_air_refs, verify_riscv, Engine, ProgramIdentity,
            RiscvMachine, RiscvProof, VerifyRiscvError, RISCV_APP_PREP_AIR_IDS,
            RISCV_REQUIRED_AIR_IDS,
        },
        primitives::{consts::MAX_NUM_PVS, layout::HEAP_END},
    };

    const FIB_ELF: &[u8] = include_bytes!("../../compiler/test_elf/fib-elf");
    /// Stacked height 2^20: Global tables of 2^19 rows.
    const LOG_STACKED_HEIGHT: usize = 20;

    /// One proved block of the fib guest, cut into more chunks than a group holds.
    struct Block {
        program: Arc<Program>,
        records: Vec<EmulationRecord>,
        machine: RiscvMachine,
        proof: RiscvProof,
    }

    fn block() -> &'static Block {
        static BLOCK: OnceLock<Block> = OnceLock::new();
        BLOCK.get_or_init(|| {
            let program = Compiler::new(SourceType::RISCV, FIB_ELF)
                .expect("the prebuilt fib ELF parses")
                .compile();
            let mut stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>();
            stdin.write(&40_000u32);
            let records = riscv::emulate(program.clone(), stdin.finalize(), Some(1 << 14));
            assert!(
                records.len() > MAX_GROUP_LEN,
                "{} chunks: the block is meant to need more than one group",
                records.len()
            );
            let machine = RiscvMachine::new(program.clone(), LOG_STACKED_HEIGHT, false)
                .expect("riscv keygen");
            let proof = machine.prove(&records).expect("the block proves");
            Block {
                program,
                records,
                machine,
                proof,
            }
        })
    }

    fn verify(proof: &RiscvProof) -> Result<(), VerifyRiscvError> {
        block().machine.verify(proof)
    }

    fn global_error(proof: &RiscvProof) -> GlobalLogUpError {
        match verify(proof) {
            Err(VerifyRiscvError::GlobalLogUp(error)) => error,
            other => panic!("expected a global LogUp error, got {other:?}"),
        }
    }

    /// The block proves and verifies, through the machine and through the stateless verifier,
    /// and has the shape the second phase is meant to have.
    #[test]
    fn a_block_proves_and_verifies() {
        let Block {
            program,
            records,
            machine,
            proof,
        } = block();
        verify(proof).expect("the machine accepts its own bundle");
        let riscv = &proof.vk.inner.params;
        let identity = ProgramIdentity::new(program, riscv).expect("the image fits");
        assert_eq!(machine.program_identity(), Some(identity));
        verify_riscv(
            proof,
            proof.vk.pre_hash,
            &[(air_id::PROGRAM, riscv::riscv_program_commit(&proof.vk))],
            &identity,
        )
        .expect("the stateless verifier accepts the bundle");

        assert_eq!(proof.chunk_proofs.len(), records.len());
        assert_eq!(
            proof.global.group_proofs.len(),
            records.len().div_ceil(MAX_GROUP_LEN)
        );
        let log_height = global_logup::global_log_height(riscv);
        assert_eq!(log_height, LOG_STACKED_HEIGHT - 1);
        for chunk_proof in &proof.chunk_proofs {
            let global = chunk_proof.trace_vdata[air_id::GLOBAL].as_ref().unwrap();
            assert_eq!(global.log_height, log_height);
        }
        assert_eq!(
            identity.image.log_height,
            global_logup::MIN_IMAGE_LOG_HEIGHT
        );
        let count = block_count(riscv, &proof.chunk_proofs);
        assert!(count > 0 && count <= global_logup::MAX_COUNT);
    }

    /// A block without one of its chunks: every chunk proof is valid, the second phase proves,
    /// and the events no longer balance.
    #[test]
    fn a_block_missing_a_chunk_does_not_balance() {
        let Block {
            records, machine, ..
        } = block();
        let partial = machine
            .prove(&records[..records.len() - 1])
            .expect("the remaining chunks prove");
        assert!(matches!(
            global_error(&partial),
            GlobalLogUpError::Unbalanced
        ));
    }

    /// A bundle with no chunk proof is refused: the recursion's root needs an execution chunk,
    /// and a program with an empty image would otherwise balance over nothing.
    #[test]
    fn a_bundle_without_chunks_is_refused() {
        let mut empty = block().proof.clone();
        empty.chunk_proofs.clear();
        assert!(matches!(global_error(&empty), GlobalLogUpError::NoChunks));
    }

    /// A run that fails part-way leaves none of its tables on the machine, where the next run's
    /// second phase would take them for its own.
    #[test]
    fn a_failed_run_leaves_no_tables_behind() {
        let Block {
            program, records, ..
        } = block();
        // A machine of its own: the block's is shared with the tests that prove on it.
        let machine = RiscvMachine::new(program.clone(), LOG_STACKED_HEIGHT, false)
            .expect("riscv keygen")
            .with_concurrency(std::num::NonZeroUsize::MIN);
        let rows = 1 << global_logup::global_log_height(chunk().engine.params());
        // Two chunks that prove, then one the commit refuses.
        let mut run = records[..2].to_vec();
        run.push(memory_record_with(rows + 1));
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| machine.prove(&run)));
        assert!(
            failed.is_err(),
            "the run was meant to fail at its third chunk"
        );
        for record in &records[..2] {
            assert!(machine
                .chunk_table_commit(record.public_values.chunk)
                .is_none());
        }
    }

    /// The second phase is bound to the chunk proofs it came with.
    #[test]
    fn a_forged_second_phase_is_rejected() {
        let honest = &block().proof;

        // The proof-of-work witness.
        let mut forged = honest.clone();
        forged.global.pow_witness += Kb::ONE;
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::ProofOfWork
        ));

        // Two chunk proofs swapped: the chain is over another order, so the challenges are not
        // the bundle's.
        let mut forged = honest.clone();
        forged.chunk_proofs.swap(0, 1);
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::ProofOfWork
        ));

        // A group left out, and a group twice.
        let mut forged = honest.clone();
        forged.global.group_proofs.pop();
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::Coverage { .. }
        ));
        let mut forged = honest.clone();
        let first = forged.global.group_proofs[0].clone();
        forged.global.group_proofs.push(first);
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::Coverage { .. }
        ));

        // The groups in another order: each still verifies, over the wrong chunks.
        let mut forged = honest.clone();
        let last = forged.global.group_proofs.len() - 1;
        if forged.global.group_proofs[0].trace_vdata.len()
            == forged.global.group_proofs[last].trace_vdata.len()
        {
            forged.global.group_proofs.swap(0, last);
            assert!(matches!(
                global_error(&forged),
                GlobalLogUpError::GroupTable {
                    group: 0,
                    table: 0,
                    chunk: 0
                }
            ));
        } else {
            forged.global.group_proofs.swap(0, last);
            assert!(matches!(
                global_error(&forged),
                GlobalLogUpError::GroupTable { .. } | GlobalLogUpError::Group { .. }
            ));
        }

        // A group that claims more tables than a group holds.
        let mut forged = honest.clone();
        let group = &mut forged.global.group_proofs[0];
        while group.trace_vdata.len() <= MAX_GROUP_LEN {
            let extra = group.trace_vdata[0].clone();
            group.trace_vdata.push(extra);
        }
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::GroupSize { group: 0, .. }
        ));

        // A group proof in the image's place.
        let mut forged = honest.clone();
        forged.global.image_proof = forged.global.group_proofs[0].clone();
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::Image(_) | GlobalLogUpError::ImageTable
        ));

        // A chunk group's sum altered.
        let mut forged = honest.clone();
        *forged.global.group_proofs[0]
            .gkr_proof
            .p0_claim
            .as_mut()
            .unwrap() += Ef::ONE;
        assert!(matches!(
            global_error(&forged),
            GlobalLogUpError::Group { group: 0, .. }
        ));
    }

    /// The image group must open the trusted image: a second phase proved over another image,
    /// under the challenges of the true program, is refused.
    #[test]
    fn a_second_phase_over_another_image_is_rejected() {
        let Block {
            program,
            machine,
            proof,
            ..
        } = block();
        let riscv = &proof.vk.inner.params;
        let mut other = (**program).clone();
        let mut image = (*other.memory_image).clone();
        let (&addr, &word) = image.iter().next().expect("the image is not empty");
        image.insert(addr, word ^ 1);
        other.memory_image = Arc::new(image);
        let other_image = ImageTable::new(&other, riscv).unwrap();
        let identity = machine.program_identity().unwrap();
        assert_ne!(other_image.commitment().commit, identity.image.commit);

        // The chunks' tables again, as the machine kept them for the honest proof.
        let chips = RiscvChipType::<Kb>::all_chips();
        let tables: Vec<ChunkTable> = block()
            .records
            .iter()
            .map(|record| commit_global_table(build_ctx(&chips, record, false), riscv).1)
            .collect();
        let vm_vk_digest = identity
            .image
            .vm_vk_digest(&riscv::riscv_program_commit(&proof.vk), &identity.pc_start);
        let logup = GlobalLogUp::new(riscv);
        let forged = logup
            .prove(&vm_vk_digest, &other_image, &tables)
            .expect("the second phase proves over any image");
        assert!(matches!(
            logup.verify(&proof.chunk_proofs, &forged, &vm_vk_digest, &identity.image),
            Err(GlobalLogUpError::ImageTable)
        ));
        // Over the true image the same call is the honest second phase.
        let (true_image, _) = (ImageTable::new(program, riscv).unwrap(), ());
        let honest = logup
            .prove(&vm_vk_digest, &true_image, &tables)
            .expect("the second phase proves");
        assert_eq!(honest.pow_witness, proof.global.pow_witness);
        logup
            .verify(&proof.chunk_proofs, &honest, &vm_vk_digest, &identity.image)
            .expect("the honest second phase verifies");
    }

    /// One commitment, two readings. The image is committed at its tier; the same stacked column
    /// read as a table of the next tier puts the kind and multiplicity columns on zeros, so a
    /// group proof over that reading opens the very same commitment and sums to nothing: the
    /// image would vanish from the block. The group proof itself is valid. What refuses it is
    /// the tier the verifier trusts for the program.
    #[test]
    fn an_image_read_at_another_tier_is_rejected() {
        let Block {
            program,
            machine,
            proof,
            records,
        } = block();
        let riscv = &proof.vk.inner.params;
        let image = ImageTable::new(program, riscv).unwrap();
        let reread = image
            .read_one_tier_up(riscv)
            .expect("the two readings are meant to share one commitment");

        let identity = machine.program_identity().unwrap();
        let vm_vk_digest = identity
            .image
            .vm_vk_digest(&riscv::riscv_program_commit(&proof.vk), &identity.pc_start);
        let chips = RiscvChipType::<Kb>::all_chips();
        let tables: Vec<ChunkTable> = records
            .iter()
            .map(|record| commit_global_table(build_ctx(&chips, record, false), riscv).1)
            .collect();
        let logup = GlobalLogUp::new(riscv);
        let forged = logup.prove(&vm_vk_digest, &reread, &tables).unwrap();

        // The group proof verifies, opens the trusted commitment, and its sum is zero.
        let root = global_logup::chain_root(
            global_logup::global_log_height(riscv),
            tables.iter().map(|table| table.commit),
        );
        let (alpha, beta) = global_logup::check_challenges(
            &logup.machines.params_digest(),
            &vm_vk_digest,
            &root,
            riscv.logup.pow_bits,
            forged.pow_witness,
        )
        .unwrap();
        let (p, q) = logup
            .verify_group(&forged.image_proof, alpha, beta)
            .unwrap();
        assert!(p == Ef::ZERO && q != Ef::ZERO);
        assert!(opens(
            &forged.image_proof,
            0,
            image.log_height + 1,
            &identity.image.commit
        ));
        // Only the height says it is not the program's image table.
        assert!(matches!(
            logup.verify(&proof.chunk_proofs, &forged, &vm_vk_digest, &identity.image),
            Err(GlobalLogUpError::ImageTable)
        ));
    }

    /// One commitment, two readings, for a chunk's table. Nothing constrains the message
    /// columns of a padding row, so a chunk can commit a table whose first five columns are
    /// free and whose last five are zero: read at the fixed height it has no events. Read as a
    /// table of half the height, the same stacked columns put cells of the fifth column under
    /// the multiplicity, and a group proof over that reading opens the very same commitment
    /// and sums an event no sender emitted. The group proof itself is valid. What refuses it
    /// is the height the verifier reads every chunk's table at.
    #[test]
    fn a_chunk_table_read_at_another_height_is_rejected() {
        let riscv = chunk().engine.params();
        let global = GlobalLogUp::new(riscv);
        let log_height = global_logup::global_log_height(riscv);
        let rows = 1usize << log_height;
        let mut table = vec![Kb::ZERO; TABLE_WIDTH * rows];
        table[0] = Kb::from_u32(7);
        table[rows / 2 * TABLE_WIDTH + 4] = Kb::ONE;
        // Ten columns of `rows` cells, laid end to end, are twenty columns of `rows / 2` cells,
        // of which the first ten hold everything that is not zero.
        let mut reread = vec![Kb::ZERO; TABLE_WIDTH * rows / 2];
        for r in 0..rows / 2 {
            for col in 0..TABLE_WIDTH {
                reread[r * TABLE_WIDTH + col] =
                    table[((col % 2) * rows / 2 + r) * TABLE_WIDTH + col / 2];
            }
        }
        assert_eq!(
            (reread[0], reread[global_logup::MULTIPLICITY_COL]),
            (Kb::from_u32(7), Kb::ONE)
        );
        let table = commit_table(RowMajorMatrix::new(table, TABLE_WIDTH), riscv);
        let reread = commit_table(RowMajorMatrix::new(reread, TABLE_WIDTH), riscv);
        let commit = table.commitment;
        assert_eq!(
            reread.commitment, commit,
            "the two readings are meant to share one commitment"
        );

        let (alpha, beta) = (Ef::from_u32(0x1234_5678), Ef::from_u32(0x0765_4321));
        let sum_of = |committed| {
            let proof = global
                .prove_committed(vec![committed], alpha, beta)
                .expect("the group proves");
            let sum = global
                .verify_group(&proof, alpha, beta)
                .expect("the group proof verifies");
            (proof, sum)
        };
        // Read at the fixed height: no events.
        let (proof, (p, q)) = sum_of(table);
        assert!(p == Ef::ZERO && q != Ef::ZERO);
        assert!(opens(&proof, 0, log_height, &commit));
        // Read at half the height: an event from nothing. Only the height tells the two apart.
        let (proof, (p, _)) = sum_of(reread);
        assert_ne!(p, Ef::ZERO);
        assert!(opens(&proof, 0, log_height - 1, &commit));
        assert!(!opens(&proof, 0, log_height, &commit));
    }

    /// The group proofs are held to the riscv machine's parameters: a second phase made by a
    /// group prover with other parameters is refused.
    #[test]
    fn a_second_phase_under_other_parameters_is_rejected() {
        let Block {
            machine,
            proof,
            records,
            program,
        } = block();
        let riscv = &proof.vk.inner.params;
        let identity = machine.program_identity().unwrap();
        let vm_vk_digest = identity
            .image
            .vm_vk_digest(&riscv::riscv_program_commit(&proof.vk), &identity.pc_start);
        let mut other = riscv.clone();
        other.logup.pow_bits -= 1;
        let chips = RiscvChipType::<Kb>::all_chips();
        let tables: Vec<ChunkTable> = records
            .iter()
            .map(|record| commit_global_table(build_ctx(&chips, record, false), riscv).1)
            .collect();
        let image = ImageTable::new(program, riscv).unwrap();
        let forged = GlobalLogUp::new(&other)
            .prove(&vm_vk_digest, &image, &tables)
            .expect("the other group prover proves");
        let mut bundle = proof.clone();
        bundle.global = forged;
        assert!(matches!(
            global_error(&bundle),
            GlobalLogUpError::ProofOfWork | GlobalLogUpError::Image(_)
        ));
    }

    /// The convert program is built for a chunk layout whose Global table sits at the operating
    /// point's one height. For the layout of the block's first chunk with the table one notch
    /// lower there is no program: a reader at another height would see other columns under the
    /// same commitment.
    #[test]
    #[should_panic(expected = "the Global air must commit one event table")]
    fn the_convert_program_needs_the_global_table_at_its_height() {
        use crate::mle::{
            compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit},
            machine::recursion::extract_recursion_vk_layout_from_heights,
        };
        let mut heights: Vec<Option<usize>> = block().proof.chunk_proofs[0]
            .trace_vdata
            .iter()
            .map(|vdata| vdata.as_ref().map(|vdata| vdata.log_height))
            .collect();
        *heights[air_id::GLOBAL].as_mut().unwrap() -= 1;
        let vk = extract_recursion_vk_layout_from_heights(&block().proof.vk, Some(&heights));
        ConvertVerifierCircuit::build_verify_program::<Kb>(&ConvertProgramInput {
            vk,
            vk_verification: false,
        });
    }

    /// A chunk layout without the Global air has no convert program either: the air is the one
    /// carrier of the chunk's public values and of its event table.
    #[test]
    #[should_panic(expected = "the Global air must be required and carry")]
    fn the_convert_program_needs_the_global_air() {
        use crate::mle::{
            compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit},
            machine::recursion::extract_recursion_vk_layout_from_heights,
        };
        let mut heights: Vec<Option<usize>> = block().proof.chunk_proofs[0]
            .trace_vdata
            .iter()
            .map(|vdata| vdata.as_ref().map(|vdata| vdata.log_height))
            .collect();
        heights[air_id::GLOBAL] = None;
        let vk = extract_recursion_vk_layout_from_heights(&block().proof.vk, Some(&heights));
        ConvertVerifierCircuit::build_verify_program::<Kb>(&ConvertProgramInput {
            vk,
            vk_verification: false,
        });
    }

    /// A chunk's Global table is committed once and read twice, by the chunk's own proof and by
    /// its group's. Both place its columns in the stacked matrix alike: a table's commitment in
    /// a group proof has the layout of the Global air's cached commitment in a chunk proof.
    #[test]
    fn a_chunk_and_its_group_lay_the_table_out_alike() {
        use crate::mle::{
            compiler::recursion::RecursionVkLayout,
            machine::recursion::extract_recursion_vk_layout_from_heights,
        };
        /// A cached commitment's stacked width and, per column, its level, row and stacked
        /// column.
        type Layout = (usize, Vec<(isize, usize, usize)>);
        /// The layouts of a key's cached commitments, with the AIR each belongs to. The commits
        /// run: the common main, then per present trace its preprocessed commitment, if it has
        /// its own, and its cached ones.
        fn cached_commits(vk: &RecursionVkLayout) -> Vec<(usize, Layout)> {
            let mut commit = 1;
            let mut out = Vec::new();
            for &air in &vk.trace_ordering {
                let structure = &vk.per_air[air];
                if !structure.is_present {
                    continue;
                }
                if vk.merged_preprocessed_commit.is_none() && structure.has_preprocessed {
                    commit += 1;
                }
                for _ in 0..structure.num_cached_mains {
                    let columns = vk.stacking_col_layout[commit]
                        .iter()
                        .map(|&(level, row, column, _)| (level, row, column))
                        .collect();
                    out.push((air, (vk.stacking_widths[commit], columns)));
                    commit += 1;
                }
            }
            assert_eq!(
                commit,
                vk.stacking_widths.len(),
                "every commit accounted for"
            );
            out
        }

        let riscv_vk = &block().proof.vk;
        let heights: Vec<Option<usize>> = block().proof.chunk_proofs[0]
            .trace_vdata
            .iter()
            .map(|vdata| vdata.as_ref().map(|vdata| vdata.log_height))
            .collect();
        let chunk = extract_recursion_vk_layout_from_heights(riscv_vk, Some(&heights));
        let in_chunk: Vec<Layout> = cached_commits(&chunk)
            .into_iter()
            .filter_map(|(air, layout)| (air == air_id::GLOBAL).then_some(layout))
            .collect();
        assert_eq!(in_chunk.len(), 1, "the Global air commits one table");

        let log_height = heights[air_id::GLOBAL].unwrap();
        let tables = 3;
        let machines = global_logup::GroupMachines::new(&riscv_vk.inner.params);
        let group = extract_recursion_vk_layout_from_heights(
            machines.vk(tables).unwrap(),
            Some(&vec![Some(log_height); tables]),
        );
        assert_eq!((group.l_skip, group.n_stack), (chunk.l_skip, chunk.n_stack));
        let in_group = cached_commits(&group);
        assert_eq!(in_group.len(), tables);
        for (_, layout) in &in_group {
            assert_eq!(layout, &in_chunk[0]);
        }
    }

    /// The image table carries a word's full 64 bits: two images that differ only above bit 32
    /// commit differently.
    #[test]
    fn the_image_table_carries_full_words() {
        let riscv = chunk().engine.params();
        let image = |word: u64| {
            let program = Program {
                memory_image: Arc::new(std::collections::BTreeMap::from([(0x1000, word)])),
                ..Default::default()
            };
            ImageTable::new(&program, riscv).unwrap().commitment()
        };
        assert_ne!(
            image(0x0000_0000_CAFE_BABE).commit,
            image(0xDEAD_BEEF_CAFE_BABE).commit
        );
    }

    /// An image word's address is a 48-bit proof address, as every address on the bus is.
    #[test]
    #[should_panic(expected = "frozen 48-bit proof address contract")]
    fn an_image_address_above_48_bits_is_refused() {
        let program = Program {
            memory_image: Arc::new(std::collections::BTreeMap::from([(1u64 << 48, 1u64)])),
            ..Default::default()
        };
        let _ = ImageTable::new(&program, chunk().engine.params());
    }

    /// The real-row limit: a block one unit over the limit is refused, by the count the
    /// verifier computes from the chunk proofs' heights.
    #[test]
    fn a_block_over_the_real_row_limit_is_rejected() {
        let Block { machine, proof, .. } = block();
        let riscv = &proof.vk.inner.params;
        let identity = machine.program_identity().unwrap();
        let vm_vk_digest = identity
            .image
            .vm_vk_digest(&riscv::riscv_program_commit(&proof.vk), &identity.pc_start);
        let logup = GlobalLogUp::new(riscv);
        let count = block_count(riscv, &proof.chunk_proofs);
        logup
            .verify_within(
                &proof.chunk_proofs,
                &proof.global,
                &vm_vk_digest,
                &identity.image,
                count,
            )
            .expect("a block at the limit is accepted");
        assert!(matches!(
            logup.verify_within(
                &proof.chunk_proofs,
                &proof.global,
                &vm_vk_digest,
                &identity.image,
                count - 1,
            ),
            Err(GlobalLogUpError::TooManyRows { count: c, max }) if c == count && max == count - 1
        ));
    }

    /// The sender table against the block: in every chunk, the bound of either direction covers
    /// the table's real rows of that direction.
    #[test]
    fn the_real_row_bound_covers_every_chunk() {
        let Block { records, proof, .. } = block();
        let riscv = &proof.vk.inner.params;
        let chips = RiscvChipType::<Kb>::all_chips();
        for (record, chunk_proof) in records.iter().zip(&proof.chunk_proofs) {
            let augmented = riscv::augmented_record(&chips, record);
            let receives = augmented
                .global_lookup_events
                .iter()
                .filter(|event| event.is_receive)
                .count() as u64;
            let sends = augmented.global_lookup_events.len() as u64 - receives;
            let share = chunk_count(riscv, |air| {
                chunk_proof.trace_vdata[air]
                    .as_ref()
                    .map(|vdata| vdata.log_height)
            });
            assert!(sends.max(receives) <= share << global_logup::LOG_COUNT_UNIT);
        }
    }

    /// A riscv key and one chunk's untouched context, for the tests that alter a Global trace.
    struct Chunk {
        engine: Engine,
        d_pk: DeviceMultiStarkProvingKey<HostPb>,
        vk: MultiStarkVerifyingKey<Sc>,
    }

    fn chunk() -> &'static Chunk {
        static CHUNK: OnceLock<Chunk> = OnceLock::new();
        CHUNK.get_or_init(|| {
            let engine: Engine = StarkEngine::new(
                pico_mle_core::config::riscv_params_with_128_bits_security(LOG_STACKED_HEIGHT),
            );
            let airs = mle_riscv_air_refs(block().program.clone(), false);
            let (pk, vk) = engine.keygen_with_app_prep_and_required(
                &airs,
                RISCV_APP_PREP_AIR_IDS,
                RISCV_REQUIRED_AIR_IDS,
            );
            let d_pk = engine.device().transport_pk_to_device(&pk);
            Chunk { engine, d_pk, vk }
        })
    }

    /// Row `i` of a Global chip trace.
    fn row(values: &mut [Kb], i: usize) -> &mut GlobalCols<Kb> {
        values[i * NUM_GLOBAL_COLS..(i + 1) * NUM_GLOBAL_COLS].borrow_mut()
    }

    /// Prove `record` alone with the Global chip's trace altered by `alter`, and say whether
    /// the chunk proof is accepted.
    fn accepted_after(record: &EmulationRecord, alter: impl FnOnce(&mut [Kb])) -> bool {
        let Chunk { engine, d_pk, vk } = chunk();
        let chips = RiscvChipType::<Kb>::all_chips();
        let mut ctx = build_ctx(&chips, record, false);
        let entry = ctx
            .per_trace
            .iter_mut()
            .find(|(air, _)| *air == air_id::GLOBAL)
            .unwrap();
        alter(&mut entry.1.common_main.values);
        let (ctx, _) = commit_global_table(ctx, engine.params());
        match engine.prove(d_pk, ctx) {
            Ok(proof) => engine.verify(vk, &proof).is_ok(),
            Err(_) => false,
        }
    }

    /// [`accepted_after`] on the block's first chunk. `alter` also gets the number of real rows,
    /// which come first.
    fn first_chunk_accepted_after(alter: impl FnOnce(&mut [Kb], usize)) -> bool {
        accepted_after(&block().records[0], |values| {
            let rows = values.len() / NUM_GLOBAL_COLS;
            let real = (0..rows)
                .filter(|&i| row(values, i).is_real == Kb::ONE)
                .count();
            assert!(
                real > 0 && real < rows,
                "the chunk has real and padding rows"
            );
            alter(values, real);
        })
    }

    /// The untouched chunk proves; each alteration of the multiplicity column is refused. A real
    /// row at zero would delete an event from the global LogUp, a real row with the sign flipped
    /// would turn a send into a receive, and a padding row off zero would invent an event.
    #[test]
    fn the_multiplicity_column_is_constrained() {
        assert!(first_chunk_accepted_after(|_, _| {}));
        assert!(!first_chunk_accepted_after(|v, _| row(v, 0).mu = Kb::ZERO));
        assert!(!first_chunk_accepted_after(|v, _| {
            let mu = row(v, 0).mu;
            row(v, 0).mu = -mu;
        }));
        assert!(!first_chunk_accepted_after(
            |v, real| row(v, real).mu = Kb::ONE
        ));
        assert!(!first_chunk_accepted_after(
            |v, real| row(v, real).mu = -Kb::ONE
        ));
    }

    /// A row's direction, kind and message are the sender's: a row with both directions set
    /// (and so a zero multiplicity), a row of another kind, a real row dropped from the table
    /// and a row added to it are each refused by the chunk's own LogUp.
    #[test]
    fn the_table_rows_are_the_senders_events() {
        assert!(!first_chunk_accepted_after(|v, _| {
            let cols = row(v, 0);
            cols.is_send = Kb::ONE;
            cols.is_receive = Kb::ONE;
            cols.mu = Kb::ZERO;
        }));
        assert!(!first_chunk_accepted_after(|v, _| row(v, 0).kind += Kb::ONE));
        assert!(!first_chunk_accepted_after(|v, real| {
            v[(real - 1) * NUM_GLOBAL_COLS..real * NUM_GLOBAL_COLS].fill(Kb::ZERO);
        }));
        assert!(!first_chunk_accepted_after(|v, real| {
            v.copy_within(0..NUM_GLOBAL_COLS, real * NUM_GLOBAL_COLS);
        }));
    }

    /// Past a chunk's events every row of the Global AIR is one row, in the committed table and
    /// in the columns beside it. The CPU prover keeps a trace's padding as one repeated leaf of
    /// its GKR input where the rows repeat the last one; were these rows to differ, a chunk being
    /// proved would hold the whole table's leaves one by one.
    #[test]
    fn the_tables_padding_repeats_one_row() {
        use crate::{
            chips::chips::riscv_global::{event::GlobalInteractionEvent, GlobalChip},
            machine::chip::ChipBehavior,
        };

        const EVENTS: usize = 5;
        let record = EmulationRecord {
            global_lookup_events: (0..EVENTS as u32)
                .map(|i| GlobalInteractionEvent {
                    message: [i + 1; 8],
                    is_receive: i % 2 == 1,
                    kind: 1,
                })
                .collect(),
            ..Default::default()
        };
        let rows =
            GlobalChip::<Kb>::default().generate_main(&record, &mut EmulationRecord::default());
        let riscv = pico_mle_core::config::riscv_params_with_128_bits_security(LOG_STACKED_HEIGHT);
        let ctx = ProvingContext::new(vec![(
            air_id::GLOBAL,
            AirProvingContext::simple_no_pis(rows),
        )]);
        let (ctx, _) = commit_global_table(ctx, &riscv);

        let global = &ctx.per_trace[0].1;
        let height = 1 << global_logup::global_log_height(&riscv);
        for matrix in [&global.cached_mains[0].trace, &global.common_main] {
            assert_eq!(matrix.height(), height);
            let width = matrix.width();
            let last = &matrix.values[(height - 1) * width..];
            assert_ne!(&matrix.values[(EVENTS - 1) * width..EVENTS * width], last);
            assert!(matrix.values[EVENTS * width..]
                .chunks_exact(width)
                .all(|row| row == last));
        }
    }

    /// Whether `record`, proved alone, gives an accepted chunk proof.
    fn record_accepted(record: &EmulationRecord) -> bool {
        accepted_after(record, |_| {})
    }

    /// The block's memory chunk.
    fn memory_record() -> &'static EmulationRecord {
        block()
            .records
            .iter()
            .find(|record| !record.memory_finalize_events.is_empty())
            .expect("the block has a memory chunk")
    }

    /// The range checks the senders rely on. A finalize event's chunk and timestamp reach the
    /// table as the first two message elements, and only the Global AIR bounds them: an event
    /// with either at `2^25`, which sender and table agree on, is refused.
    #[test]
    fn out_of_range_finalize_events_are_refused() {
        let record = memory_record();
        assert!(record_accepted(record));
        let mut late = record.clone();
        late.memory_finalize_events[0].timestamp = 1 << 25;
        assert!(!record_accepted(&late));
        let mut far = record.clone();
        far.memory_finalize_events[0].chunk = 1 << 25;
        assert!(!record_accepted(&far));
    }

    /// The first message element is 25 bits as a u16 limb, a u8 limb and a high bit, each of
    /// them checked. `2^24` is in range as the high bit alone; the same value written as a u8
    /// limb of 256, with sender and table still agreeing on the message, is refused.
    #[test]
    fn the_limbs_of_the_first_message_element_are_range_checked() {
        let mut record = memory_record().clone();
        let event = record
            .memory_finalize_events
            .iter_mut()
            .find(|event| event.addr >= 0x1000)
            .expect("a word past the registers");
        event.chunk = 1 << 24;
        assert!(record_accepted(&record));
        assert!(!accepted_after(&record, |values| {
            let at = (0..values.len() / NUM_GLOBAL_COLS)
                .find(|&i| row(values, i).message[0] == Kb::from_u32(1 << 24))
                .expect("the event's row");
            let cols = row(values, at);
            assert_eq!(cols.message_0_high_bit, Kb::ONE);
            cols.message_0_high_bit = Kb::ZERO;
            cols.message_0_8bit_limb = Kb::from_u32(1 << 8);
        }));
    }

    /// The last message element is the chunk on a syscall message, and nothing but the table
    /// bounds it there: the Global AIR looks that column up as a u16, with the multiplicity all
    /// its range checks share.
    #[test]
    fn the_last_message_element_is_range_checked() {
        let dag = &chunk().vk.inner.per_air[air_id::GLOBAL].symbolic_constraints;
        let node = |at: usize| &dag.constraints.nodes[at];
        let global = dag
            .interactions
            .iter()
            .find(|interaction| interaction.kind == LookupType::Global)
            .expect("the AIR receives on the Global bus");
        let last = node(global.message[7]);
        assert!(matches!(last, SymbolicExpressionNode::Variable(_)));
        let u16_range = SymbolicExpressionNode::Constant(Kb::from_u8(ByteOpcode::U16Range as u8));
        let zero = SymbolicExpressionNode::Constant(Kb::ZERO);
        let lookups: Vec<_> = dag
            .interactions
            .iter()
            .filter(|interaction| interaction.kind == LookupType::Byte)
            .map(|interaction| {
                let message: Vec<_> = interaction.message.iter().map(|&at| node(at)).collect();
                (message, node(interaction.count))
            })
            .collect();
        let is_real = lookups[0].1;
        assert!(matches!(is_real, SymbolicExpressionNode::Variable(_)));
        assert!(lookups.iter().all(|(_, count)| *count == is_real));
        assert!(lookups
            .iter()
            .any(|(message, _)| message[..] == [&u16_range, last, &zero, &zero, &zero]));
    }

    /// The block's memory chunk with words added to finalize, for `events` cross-chunk events
    /// in all. The words follow the last one below the stack guard.
    fn memory_record_with(events: usize) -> EmulationRecord {
        let mut record = memory_record().clone();
        let more =
            events - record.memory_initialize_events.len() - record.memory_finalize_events.len();
        let finalize = &mut record.memory_finalize_events;
        assert!(finalize.is_sorted_by_key(|event| event.addr));
        let at = finalize.partition_point(|event| event.addr < HEAP_END);
        assert!(
            0 < at && at < finalize.len(),
            "the chunk finalizes words on both sides of the stack guard"
        );
        let last = finalize[at - 1];
        let base = last.addr.max(1 << 20) & !7;
        assert!(base + 8 * (more as u64) < HEAP_END);
        finalize.splice(
            at..at,
            (1..=more as u64).map(|k| MemoryInitializeFinalizeEvent {
                addr: base + 8 * k,
                ..last
            }),
        );
        record
    }

    /// A chunk whose events fill its table to the last row proves.
    #[test]
    fn a_chunk_that_fills_its_table_proves() {
        let rows = 1 << global_logup::global_log_height(chunk().engine.params());
        assert!(accepted_after(&memory_record_with(rows), |values| {
            assert_eq!(values.len(), rows * NUM_GLOBAL_COLS);
            assert!(
                (0..rows).all(|i| row(values, i).is_real == Kb::ONE),
                "every row of the table is an event"
            );
        }));
    }

    /// One event more than the table holds does not reach a proof. The emulator cuts chunks so
    /// that no chunk has that many (`emulator::riscv::chunk_split`, `record`); the commit
    /// refuses one that does.
    #[test]
    #[should_panic(expected = "more cross-chunk events")]
    fn a_chunk_with_more_events_than_its_table_holds_is_refused() {
        let rows = 1 << global_logup::global_log_height(chunk().engine.params());
        record_accepted(&memory_record_with(rows + 1));
    }

    /// Whether `chip`'s constraints refuse `row` for holding `value` where a boolean belongs.
    fn refused_as_non_boolean<A>(chip: &A, row: &[Kb], value: Kb) -> bool
    where
        A: for<'a> Air<DebugConstraintFolder<'a, Kb, Ef>>,
    {
        let zero = [Kb::ZERO];
        let public_values = [Kb::ZERO; MAX_NUM_PVS];
        let mut folder = DebugConstraintFolder::<Kb, Ef> {
            preprocessed: RowWindow::from_two_rows(&zero, &zero),
            main: RowWindow::from_two_rows(row, row),
            is_first_row: Kb::ZERO,
            is_last_row: Kb::ZERO,
            is_transition: Kb::ZERO,
            public_values: &public_values,
            failures: Vec::new(),
            scopes: Vec::new(),
            constraint_count: 0,
        };
        chip.eval(&mut folder);
        folder.failures.iter().any(
            |(_, failure)| matches!(failure, DebugConstraintFailure::NonBoolean(x) if *x == value),
        )
    }

    /// Every sender's multiplicity on the Global bus is a boolean in the sender's own AIR: a
    /// row with a multiplicity of 2 or -1, which would count one event twice or turn a send
    /// into a receive, is refused there. [`GLOBAL_SENDERS`] and the real-row bound count on it.
    #[test]
    fn a_senders_multiplicity_is_boolean() {
        for value in [Kb::TWO, Kb::NEG_ONE] {
            // MemoryLocal: each entry's send (`is_real`) and receive (`has_initial`).
            for entry in 0..LOCAL_MEMORY_DATAPAR {
                for receive in [false, true] {
                    let mut row = [Kb::ZERO; NUM_MEMORY_LOCAL_INIT_COLS];
                    let cols: &mut MemoryLocalCols<Kb> = row.as_mut_slice().borrow_mut();
                    let slot = &mut cols.memory_local_entries[entry];
                    if receive {
                        slot.has_initial = value;
                    } else {
                        slot.is_real = value;
                    }
                    assert!(refused_as_non_boolean(
                        &MemoryLocalChip::<Kb>::default(),
                        &row,
                        value
                    ));
                }
            }
            for kind in [MemoryChipType::Initialize, MemoryChipType::Finalize] {
                let mut row = [Kb::ZERO; NUM_MEMORY_INITIALIZE_FINALIZE_COLS];
                let cols: &mut MemoryInitializeFinalizeCols<Kb> = row.as_mut_slice().borrow_mut();
                cols.is_real = value;
                let chip = MemoryInitializeFinalizeChip::<Kb>::new(kind);
                assert!(refused_as_non_boolean(&chip, &row, value));
            }
            for chip in [SyscallChip::<Kb>::riscv(), SyscallChip::<Kb>::precompile()] {
                let mut row = [Kb::ZERO; NUM_SYSCALL_COLS];
                let cols: &mut SyscallCols<Kb> = row.as_mut_slice().borrow_mut();
                cols.is_real = value;
                assert!(refused_as_non_boolean(&chip, &row, value));
            }
        }
    }

    /// The kind is part of the message. A send and a receive that agree on every message
    /// element cancel when they are of one kind; a memory send and a syscall receive do not,
    /// so a block that relied on the pair has a sum off zero
    /// ([`GlobalLogUpError::Unbalanced`]).
    #[test]
    fn a_send_and_a_receive_of_two_kinds_do_not_cancel() {
        let riscv = chunk().engine.params();
        let global = GlobalLogUp::new(riscv);
        let log_height = global_logup::global_log_height(riscv);
        let (alpha, beta) = (Ef::from_u32(0x1234_5678), Ef::from_u32(0x0765_4321));
        let sum = |receive: LookupType| {
            let mut values = Vec::new();
            for (kind, mu) in [(LookupType::Memory, Kb::ONE), (receive, Kb::NEG_ONE)] {
                values.extend([3, 5, 7, 11, 13, 17, 19, 23].map(Kb::from_u32));
                values.extend([Kb::from_u8(kind as u8), mu]);
            }
            let table = RowMajorMatrix::new(values, TABLE_WIDTH);
            let committed = commit_table(padded(&table, log_height), riscv);
            let proof = global
                .prove_committed(vec![committed], alpha, beta)
                .expect("the group proves");
            global
                .verify_group(&proof, alpha, beta)
                .expect("the group proof verifies")
        };
        let (p, q) = sum(LookupType::Memory);
        assert!(p == Ef::ZERO && q != Ef::ZERO, "one kind: the pair cancels");
        let (p, _) = sum(LookupType::Syscall);
        assert_ne!(p, Ef::ZERO, "two kinds: the pair does not cancel");
    }

    /// A chunk proof without the Global AIR is not a chunk proof: the AIR is required, so the
    /// verifier refuses the proof's shape.
    #[test]
    fn a_chunk_proof_without_the_global_air_is_refused() {
        let Chunk { engine, vk, .. } = chunk();
        let mut proof = block().proof.chunk_proofs[0].clone();
        engine.verify(vk, &proof).expect("the chunk proof verifies");
        proof.trace_vdata[air_id::GLOBAL] = None;
        assert!(matches!(
            engine.verify(vk, &proof),
            Err(VerifierError::ProofShapeError(_))
        ));
    }

    /// A key whose Global bus is not the audited one is refused: a second receiver could absorb
    /// events that never reach the table, and a sender outside the table is not counted by the
    /// real-row bound.
    #[test]
    fn a_key_with_another_global_bus_is_refused() {
        let honest = &chunk().vk.inner;
        check_global_bus(honest).expect("the machine's own key passes");
        let global_interaction = |air: usize, vk: &MultiStarkVerifyingKeyInner<Sc>| {
            vk.per_air[air]
                .symbolic_constraints
                .interactions
                .iter()
                .position(|interaction| interaction.kind == LookupType::Global)
                .expect("the AIR is on the Global bus")
        };

        // A sender turned into a receiver.
        let mut second_receiver = honest.clone();
        let at = global_interaction(air_id::SYSCALL_RISCV, honest);
        second_receiver.per_air[air_id::SYSCALL_RISCV]
            .symbolic_constraints
            .interactions[at]
            .count_weight = 0;
        assert!(check_global_bus(&second_receiver)
            .unwrap_err()
            .contains("exactly one receiving interaction"));

        // A sender missing, and a sender the table does not list.
        let mut missing_sender = honest.clone();
        let at = global_interaction(air_id::MEM_FINAL, honest);
        missing_sender.per_air[air_id::MEM_FINAL]
            .symbolic_constraints
            .interactions
            .remove(at);
        assert!(check_global_bus(&missing_sender)
            .unwrap_err()
            .contains("not the audited table"));
        let mut extra_sender = honest.clone();
        let at = global_interaction(air_id::MEM_INIT, honest);
        let sender = extra_sender.per_air[air_id::MEM_INIT]
            .symbolic_constraints
            .interactions[at]
            .clone();
        extra_sender.per_air[air_id::MEM_INIT]
            .symbolic_constraints
            .interactions
            .push(sender);
        assert!(check_global_bus(&extra_sender)
            .unwrap_err()
            .contains("not the audited table"));

        // A sender whose direction is not one of the two literal pairs: both bits set, and a
        // bit read from a column.
        let direction = GLOBAL_KIND_VALUE_INDEX - 2;
        let at = global_interaction(air_id::MEM_INIT, honest);
        let mut both_directions = honest.clone();
        let message = &mut both_directions.per_air[air_id::MEM_INIT]
            .symbolic_constraints
            .interactions[at]
            .message;
        message[direction + 1] = message[direction];
        assert!(check_global_bus(&both_directions)
            .unwrap_err()
            .contains("without a literal direction"));
        let mut direction_column = honest.clone();
        let message = &mut direction_column.per_air[air_id::MEM_INIT]
            .symbolic_constraints
            .interactions[at]
            .message;
        message[direction] = message[2];
        assert!(check_global_bus(&direction_column)
            .unwrap_err()
            .contains("without a literal direction"));
    }

    /// The Global AIR as keygen sees it: required, the table in a cached partition of its own,
    /// one receiving interaction on the Global bus, and the five byte lookups of the range
    /// checks.
    #[test]
    fn the_global_air_is_pinned() {
        let air = &chunk().vk.inner.per_air[air_id::GLOBAL];
        assert!(air.is_required);
        assert_eq!(air.params.width.cached_mains, [TABLE_WIDTH]);
        assert_eq!(air.params.width.common_main, NUM_GLOBAL_AUX_COLS);
        assert_eq!(
            air.params.num_public_values,
            crate::primitives::consts::MAX_NUM_PVS
        );
        let dag = &air.symbolic_constraints;
        assert_eq!(dag.constraints.constraint_idx.len(), 8);
        // The zerocheck rule count keygen derives for the AIR.
        assert_eq!(
            crate::chips::tests::reachable_constraint_nodes(&dag.constraints),
            37
        );
        let kinds: Vec<(LookupType, u32)> = dag
            .interactions
            .iter()
            .map(|interaction| (interaction.kind, interaction.count_weight))
            .collect();
        assert_eq!(
            kinds,
            [
                (LookupType::Global, 0),
                (LookupType::Byte, 1),
                (LookupType::Byte, 1),
                (LookupType::Byte, 1),
                (LookupType::Byte, 1),
                (LookupType::Byte, 1),
            ]
        );
        assert_global_bus(&chunk().vk.inner);
    }
}
