mod memory;
mod opcode;
pub mod profile;

use std::{
    array,
    borrow::Borrow,
    collections::VecDeque,
    fmt::Debug,
    io::{stdout, Write},
    iter::zip,
    marker::PhantomData,
    sync::Arc,
};

use crate::{
    chips::chips::recursion_memory::MemEvent,
    compiler::recursion::{ir::Block, program::RecursionProgram},
    emulator::{record::RecordBehavior, recursion::emulator::memory::MemVecMap},
    machine::septic::{SepticCurve, SepticExtension},
};
use backtrace::Backtrace as Trace;
use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::{
    BasedVectorSpace, ExtensionField, Field, InjectiveMonomial, PrimeCharacteristicRing,
    PrimeField32,
};
use p3_poseidon2::{ExternalLayer, InternalLayer, Poseidon2};
use p3_symmetric::Permutation;
use p3_util::reverse_bits_len;

use crate::compiler::recursion::types::{
    AssertZeroExtEvent, AssertZeroExtInstr, BaseAluEvent, BaseAluInstr, BatchFRIBaseVecIo,
    BatchFRIEvent, BatchFRIExtSingleIo, BatchFRIExtVecIo, BatchFRIInstr, BinaryFoldStepEvent,
    BinaryFoldStepInstr, CommitPublicValuesEvent, DigestSelectEvent, DigestSelectInstr,
    ExpBitsLenEvent, ExpBitsLenInstr, ExpReverseBitsEvent, ExpReverseBitsInstr, ExpReverseBitsIo,
    ExtAluEvent, ExtAluInstr, ExtDotProductEvent, ExtDotProductInstr, FracFoldEvent, FracFoldInstr,
    GkrSumcheckRoundEvent, GkrSumcheckRoundInstr, HornerEvalEvent, HornerEvalInstr,
    LagrangeEvalD2Event, LagrangeEvalD2Instr, MemAccessKind, MemInstr, MemIo, MleOpenEvent,
    MleOpenInstr, PackBlockEvent, PackBlockInstr, Poseidon2Event, Poseidon2Instr, Poseidon2Io,
    Poseidon2PackedInstr, SelectEvent, SelectInstr, SelectIo, UnivariateFoldEvent,
    UnivariateFoldInstr, UnpackBlockEvent, UnpackBlockInstr,
};
use thiserror::Error;

pub use crate::emulator::recursion::record::*;
use crate::{
    compiler::recursion::instruction::{
        FieldEltType, HintAddCurveInstr, HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction,
        PrintInstr,
    },
    primitives::consts::{
        DIGEST_BLOCKS, DIGEST_SIZE, EMULATOR_POSEIDON2_LEN, EXTENSION_DEGREE,
        EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS, HORNER_EVAL_DATAPAR, PACK_LANES,
        PERMUTATION_WIDTH, PERM_BLOCKS, RECURSION_NUM_PVS,
    },
};
pub use memory::DepthTrack;

/// Permutes every state in place; see `Runtime::batch_perm`.
pub type BatchPerm<F> = Arc<dyn Fn(&mut [[F; PERMUTATION_WIDTH]]) + Send + Sync>;

/// Every event vector of `RecursionRecord`, for the planned run's re-ordering. `event_lens`
/// destructures the record with this list, so a vector added to the record and not here does not
/// compile.
macro_rules! record_event_vecs {
    ($m:ident) => {
        $m!(
            base_alu_events,
            ext_alu_events,
            mem_var_events,
            select_events,
            poseidon2_events,
            exp_reverse_bits_len_events,
            exp_bits_len_events,
            batch_fri_events,
            commit_pv_hash_events,
            assert_zero_ext_events,
            frac_fold_events,
            univariate_fold_events,
            mle_open_events,
            lagrange_eval_d2_events,
            gkr_sumcheck_round_events,
            ext_dot_product_events,
            horner_eval_events,
            digest_select_events,
            binary_fold_step_events,
            pack_block_events,
            unpack_block_events,
            poseidon2_packed_events
        )
    };
}
const RECORD_EVENT_VECS: usize = 22;

/// The window the prover's plans use: wide enough that 93-98% of a recursion program's
/// permutations land in levels of 16 or more, small enough to stay in cache.
pub const WAVEFRONT_WINDOW: usize = 16384;

/// The order a planned run takes through `instructions[from..to]`, and where each event it pushes
/// lands in program order. A property of the program alone: its addresses are static and it has
/// no control flow, so every emulation of it has the same dependencies and pushes the same events
/// per instruction.
///
/// The order is level by level of data dependency within consecutive windows of `window`
/// instructions, so each level's `Poseidon2Packed` permutations can be computed as one batch
/// ([`Runtime::batch_perm`]); the windows keep the working set in cache. Any such order is
/// topological: every dependency of a window is in it or in an earlier one.
#[derive(Debug, Default, Clone)]
pub struct WavefrontPlan {
    /// Instruction indices, level by level; within a level the others first, then the
    /// `Poseidon2Packed` ones, each part in program order.
    pub order: Vec<u32>,
    /// Per level `(start, poseidon2_start, end)` positions in `order`.
    pub levels: Vec<(u32, u32, u32)>,
    /// Per event vector: the program-order slot of each event, in the order the run pushes them.
    pub dest: [Vec<u32>; RECORD_EVENT_VECS],
}

impl WavefrontPlan {
    /// `depth` and `entries` come from [`Runtime::census`]; `is_p2` says which instructions are
    /// `Poseidon2Packed`; level order is taken within consecutive windows of `window`.
    pub fn new(
        from: usize,
        to: usize,
        depth: &[u32],
        entries: &[(u32, u8, u32)],
        window: usize,
        is_p2: impl Fn(usize) -> bool,
    ) -> Self {
        let mut order: Vec<u32> = (from as u32..to as u32).collect();
        let mut levels = Vec::new();
        let mut base = 0usize;
        for w in order.chunks_mut(window.max(1)) {
            w.sort_unstable_by_key(|&i| (depth[i as usize], is_p2(i as usize), i));
            let mut i = 0;
            while i < w.len() {
                let d = depth[w[i] as usize];
                let a = i;
                while i < w.len() && depth[w[i] as usize] == d && !is_p2(w[i] as usize) {
                    i += 1;
                }
                let m = i;
                while i < w.len() && depth[w[i] as usize] == d {
                    i += 1;
                }
                levels.push(((base + a) as u32, (base + m) as u32, (base + i) as u32));
            }
            base += w.len();
        }
        // Per vector: each instruction's events and its first program-order slot.
        let mut counts: [hashbrown::HashMap<u32, (u32, u32)>; RECORD_EVENT_VECS] =
            std::array::from_fn(|_| hashbrown::HashMap::new());
        let mut next = [0u32; RECORD_EVENT_VECS];
        for &(idx, k, c) in entries {
            if (idx as usize) < from || (idx as usize) >= to {
                continue;
            }
            let k = k as usize;
            counts[k].insert(idx, (next[k], c));
            next[k] += c;
        }
        let mut dest: [Vec<u32>; RECORD_EVENT_VECS] = std::array::from_fn(|_| Vec::new());
        for &idx in &order {
            for k in 0..RECORD_EVENT_VECS {
                if let Some(&(first, c)) = counts[k].get(&idx) {
                    dest[k].extend(first..first + c);
                }
            }
        }
        Self {
            order,
            levels,
            dest,
        }
    }
}
use memory::*;
pub use opcode::*;
pub use profile::{dump_emulation, EmulateProfile};

/// Whether this instruction writes a constant: it reads no address, so it can be evaluated at
/// any point before its readers, which is what lets `Runtime::run_split` hoist these ahead of
/// its fork.
pub fn is_const_write<F>(instruction: &Instruction<F>) -> bool {
    matches!(
        instruction,
        Instruction::Mem(MemInstr {
            kind: MemAccessKind::Write,
            ..
        })
    )
}

#[derive(Debug, Clone, Default)]
pub struct CycleTrackerEntry {
    pub span_entered: bool,
    pub span_enter_cycle: usize,
    pub cumulative_cycles: usize,
}

pub struct Runtime<'a, F, EF, ExternalPerm, InternalPerm, const D: u64>
where
    F: PrimeField32 + Field + InjectiveMonomial<D>,
    EF: ExtensionField<F>,
    ExternalPerm: ExternalLayer<F, PERMUTATION_WIDTH, D>,
    InternalPerm: InternalLayer<F, PERMUTATION_WIDTH, D>,
{
    pub timestamp: usize,

    pub nb_poseidons: usize,

    pub nb_wide_poseidons: usize,

    pub nb_bit_decompositions: usize,

    pub nb_ext_ops: usize,

    pub nb_base_ops: usize,

    pub nb_memory_ops: usize,

    pub nb_branch_ops: usize,

    pub nb_select: usize,

    pub nb_exp_reverse_bits: usize,

    pub nb_batch_fri: usize,

    pub nb_print_f: usize,

    pub nb_print_e: usize,

    /// The current clock.
    pub clk: F,

    /// The program counter.
    pub pc: F,

    /// The program.
    pub program: Arc<RecursionProgram<F>>,

    /// Memory. From canonical usize of an Address to a MemoryEntry.
    pub memory: MemVecMap<F>,

    /// The data-dependency depth of each executed instruction while `memory.depth` is set
    /// ([`Self::census`]).
    pub depth_log: Vec<u32>,

    /// The emulation record.
    pub record: RecursionRecord<F>,

    pub witness_stream: VecDeque<Block<F>>,

    pub cycle_tracker: HashMap<String, CycleTrackerEntry>,

    /// The stream that print statements write to.
    /// `Send` so a node's two children can be interpreted on two threads (`run_split`).
    pub debug_stdout: Box<dyn Write + Send + 'a>,

    /// Entries for dealing with the Poseidon2 hash state.
    perm: Option<Poseidon2<F, ExternalPerm, InternalPerm, PERMUTATION_WIDTH, D>>,

    /// Permutes many independent states at once, for a planned run's Poseidon2 batches. `None`
    /// permutes them one at a time with `perm`. Set by the caller, which knows the concrete field
    /// and its packing.
    pub batch_perm: Option<BatchPerm<F>>,

    /// When set, `run_split` runs each child by its plan ([`Self::run_range_planned`]).
    pub child_plans: Option<Arc<[WavefrontPlan; 2]>>,

    /// Which layer this emulation belongs to (`convert` / `combine`), for the profile and dump
    /// lines only. A recursion program does not otherwise know, and the two cost very
    /// differently: only combine's sits on the proof tree's serial chain.
    pub dump_label: &'static str,

    _marker_ef: PhantomData<EF>,
}

#[derive(Error, Debug)]
pub enum RuntimeError<F: Debug, EF: Debug> {
    #[error(
        "attempted to perform base field division {in1:?}/{in2:?} \
        from instruction {instr:?} at pc {pc:?}\nnearest pc with backtrace:\n{trace:?}"
    )]
    DivFOutOfDomain {
        in1: F,
        in2: F,
        instr: BaseAluInstr<F>,
        pc: usize,
        trace: Option<(usize, Trace)>,
    },
    #[error(
        "attempted to perform extension field division {in1:?}/{in2:?} \
        from instruction {instr:?} at pc {pc:?}\nnearest pc with backtrace:\n{trace:?}"
    )]
    DivEOutOfDomain {
        in1: EF,
        in2: EF,
        instr: ExtAluInstr<F>,
        pc: usize,
        trace: Option<(usize, Trace)>,
    },
    #[error("failed to print to `debug_stdout`: {0}")]
    DebugPrint(#[from] std::io::Error),
    #[error("attempted to read from empty witness stream")]
    EmptyWitnessStream,
}

impl<F, EF, ExternalPerm, InternalPerm, const D: u64>
    Runtime<'_, F, EF, ExternalPerm, InternalPerm, D>
where
    F: PrimeField32 + Field + InjectiveMonomial<D>,
    EF: ExtensionField<F>,
    ExternalPerm: ExternalLayer<F, PERMUTATION_WIDTH, D>,
    InternalPerm: InternalLayer<F, PERMUTATION_WIDTH, D>,
{
    pub fn new(
        program: Arc<RecursionProgram<F>>,
        perm: Poseidon2<F, ExternalPerm, InternalPerm, PERMUTATION_WIDTH, D>,
    ) -> Self {
        let record = RecursionRecord::<F> {
            program: program.clone(),
            poseidon2_events: Vec::with_capacity(EMULATOR_POSEIDON2_LEN), //put 7_100_000 for block reth-17106222 which is the maximum
            ..Default::default()
        };
        let memory = Memory::with_capacity(program.total_memory);
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_wide_poseidons: 0,
            nb_bit_decompositions: 0,
            nb_select: 0,
            nb_exp_reverse_bits: 0,
            nb_batch_fri: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_branch_ops: 0,
            nb_print_f: 0,
            nb_print_e: 0,
            depth_log: Vec::new(),
            clk: F::ZERO,
            program,
            pc: F::ZERO,
            memory,
            record,
            witness_stream: VecDeque::new(),
            cycle_tracker: HashMap::new(),
            debug_stdout: Box::new(stdout()),
            perm: Some(perm),
            batch_perm: None,
            child_plans: None,
            dump_label: "",
            _marker_ef: PhantomData,
        }
    }

    pub fn print_stats(&self) {
        // print all stats
        tracing::info!("   |- {:<26}: {}", "Total Cycles:", self.timestamp);
        tracing::info!(
            "   |- {:<26}: {}",
            "Poseidon Operations:",
            self.nb_poseidons
        );
        tracing::info!(
            "   |- {:<26}: {}",
            "Exp Reverse Bits Operations:",
            self.nb_exp_reverse_bits
        );
        tracing::info!(
            "   |- {:<26}: {}",
            "BatchFRI Operations:",
            self.nb_batch_fri
        );
        tracing::info!("   |- {:<26}: {}", "Field Operations:", self.nb_base_ops);
        tracing::info!("   |- {:<26}: {}", "Extension Operations:", self.nb_ext_ops);
        tracing::info!("   |- {:<26}: {}", "Memory Operations:", self.nb_memory_ops);
        tracing::info!("   |- {:<26}: {}", "Branch Operations:", self.nb_branch_ops);

        for (name, entry) in self.cycle_tracker.iter().sorted_by_key(|(name, _)| *name) {
            tracing::info!("> {}: {}", name, entry.cumulative_cycles);
        }
    }

    fn nearest_pc_backtrace(&mut self) -> Option<(usize, Trace)> {
        let trap_pc = self.pc.as_canonical_u32() as usize;
        let trace = self.program.traces.get(trap_pc).cloned()?;
        if let Some(mut trace) = trace {
            trace.resolve();
            Some((trap_pc, trace))
        } else {
            (0..trap_pc)
                .rev()
                .filter_map(|nearby_pc| {
                    let mut trace = self.program.traces.get(nearby_pc)?.clone()?;
                    trace.resolve();
                    Some((nearby_pc, trace))
                })
                .next()
        }
    }

    /// Interpret the whole program.
    pub fn run(&mut self) -> Result<(), RuntimeError<F, EF>> {
        self.run_range(0, self.program.instructions.len(), false, "all")
    }

    /// A child's own interpreter: this program, this slice of the witness, its own memory and
    /// record, and `base` for everything the prologue already wrote.
    ///
    /// Not `Runtime::new`: that reserves `EMULATOR_POSEIDON2_LEN` Poseidon2 events, which is
    /// ~866 MB and sized for a RISC-V chunk. A child needs what its own range emits, which the
    /// range's length estimates closely enough that a wrong guess costs one doubling.
    fn fork(
        &self,
        base: &Arc<vec_map::VecMap<MemoryEntry<F>>>,
        witness_stream: VecDeque<Block<F>>,
        instruction_count: usize,
    ) -> Self
    where
        ExternalPerm: Clone,
        InternalPerm: Clone,
    {
        // Sizes `poseidon2_packed_events` — of the two Poseidon2 vectors it is the one the MLE
        // builders fill. Roughly one instruction in eight: 65,790 of 568,103 on the reth-188
        // combine dumps, 11.6 %.
        // A reservation, not a count: counting means a pass over a quarter-million instructions
        // for something a wrong guess only costs a doubling of.
        let p2 = instruction_count / 8;
        Self {
            timestamp: 0,
            nb_poseidons: 0,
            nb_wide_poseidons: 0,
            nb_bit_decompositions: 0,
            nb_ext_ops: 0,
            nb_base_ops: 0,
            nb_memory_ops: 0,
            nb_branch_ops: 0,
            nb_select: 0,
            nb_exp_reverse_bits: 0,
            nb_batch_fri: 0,
            nb_print_f: 0,
            nb_print_e: 0,
            depth_log: Vec::new(),
            clk: F::ZERO,
            pc: F::ZERO,
            program: Arc::clone(&self.program),
            memory: MemVecMap {
                map: vec_map::VecMap::new(),
                bases: [Some(Arc::clone(base)), None],
                written: None,
                depth: None,
            },
            record: RecursionRecord::<F> {
                program: Arc::clone(&self.program),
                poseidon2_packed_events: Vec::with_capacity(p2),
                ..Default::default()
            },
            witness_stream,
            cycle_tracker: HashMap::new(),
            // Real stdout, not a sink: `Instruction::Print` is a debugging aid and swallowing it
            // in one half of a split node would be a silent difference between the two paths.
            debug_stdout: Box::new(stdout()),
            perm: self.perm.clone(),
            batch_perm: self.batch_perm.clone(),
            child_plans: None,
            dump_label: self.dump_label,
            _marker_ef: PhantomData,
        }
    }

    /// Interpret a combine node's two children concurrently.
    ///
    /// The program is prologue | child 0 | child 1 | merge (`RecursionProgram::child_spans`).
    ///
    /// What makes the two children separable was measured, by charging every read against
    /// whoever wrote the address: on the combine nodes measured, the values written inside
    /// child 0 and read outside it are read **only by the merge tail** —
    /// which runs after the join — never by child 1. That is the property this relies on, and it
    /// belongs to the circuit the builder emits rather than to anything enforced here. It does
    /// not fail quietly: a child reading an address the other wrote finds it in neither its own
    /// table nor the frozen base, and `mr` panics on the unassigned address.
    ///
    /// The prologue is `init_constants`, seven writes, and runs first. Every
    /// `Instruction::Mem(Write)` inside the two children is also evaluated ahead of the fork,
    /// because `const_f` memoises its constants *across* children and emits each one
    /// where it is first used — which can be inside child 0, with child 1 reading it. Those
    /// writes read nothing, so evaluating them early is free of order.
    ///
    /// Each child then reads the frozen table through an `Arc` and writes its own. Their address
    /// ranges cannot collide: the builder's allocator is a strictly monotone bump. The records
    /// are concatenated in child order, which is program order because every instruction of
    /// child 0 precedes every instruction of child 1.
    ///
    /// The program runs either way. `Ok(false)` means it ran serially because this did not
    /// recognise its shape — the bool is for the log line, not an instruction to the caller, so
    /// dropping it costs a fact and never a run. (An earlier shape returned "did nothing";
    /// `run_split().expect(..)` then compiled into an empty record.)
    ///
    /// `Err` is terminal either way — from the serial fallback, which has run part of the
    /// program, or from after the fork, by which point the memory table has moved into the
    /// shared base and both children's hints are drained. A caller that catches one must drop
    /// the runtime, not retry on it.
    ///
    /// On by default (`MLE_REC_PARALLEL_CHILDREN=0` opts out).
    ///
    /// One extra OS thread per node — child 1 runs on the caller's own — spawned inside
    /// whatever pool the caller is in, today one rayon worker per node. Peak memory is about
    /// three memory tables where the serial path holds one: the frozen base, plus a child's
    /// each. Both costs are per node being emulated, so they scale with the tree's width — the
    /// table is 24 bytes per address over `total_memory`, which on the reth-188 dumps
    /// (`total_memory` 920,999) is 22 MB.
    pub fn run_split(&mut self) -> Result<bool, RuntimeError<F, EF>>
    where
        F: Send + Sync,
        EF: Send,
        ExternalPerm: Clone + Send + Sync,
        InternalPerm: Clone + Send + Sync,
    {
        let program = Arc::clone(&self.program);
        let spans = program.child_spans.clone();
        let [(s0, e0), (s1, e1)] = spans[..] else {
            return self.run().map(|()| false);
        };
        // `reset_sponge` between the children emits no instruction, so the ranges abut. Anything
        // else — ranges out of order, out of bounds, or with a gap holding code this would skip
        // — is a program shape this does not understand, and it runs serially instead. The field
        // is public and a replayed program restores it from a file, so this is not a formality.
        if !(s0 <= e0 && e0 == s1 && s1 <= e1 && e1 <= program.instructions.len()) {
            return self.run().map(|()| false);
        }
        // `RECURSION_EARLY_EXIT_TS` stops the interpreter at a timestamp. Each child counts its
        // own from zero, so under a split the budget would silently become one per child. The
        // decline shows up as `split = 0` on the timing line.
        if std::env::var_os("RECURSION_EARLY_EXIT_TS").is_some() {
            return self.run().map(|()| false);
        }
        // The merge folds the prologue's record in after child 0's, which is the serial order
        // only while the prologue emits no events — it is `init_constants` today, all constant
        // writes. Declined here, before any work, because the contract is that a decline has
        // done nothing and the caller reruns from the top.
        if !program.instructions[..s0].iter().all(is_const_write) {
            return self.run().map(|()| false);
        }
        // Each child gets the witness blocks its own range reads. Counted here rather than at the
        // fork because a stream too short to serve both would panic in `drain`, where the serial
        // path returns `EmptyWitnessStream` at the offending instruction — and by the fork the
        // prologue has run, so declining there would no longer be free.
        let hints = |r: std::ops::Range<usize>| -> usize {
            program.instructions[r]
                .iter()
                .map(Instruction::witness_blocks)
                .sum()
        };
        let (h0, h1) = (hints(s0..e0), hints(s1..e1));
        if h0 + h1 > self.witness_stream.len() {
            return self.run().map(|()| false);
        }

        let t_pro = std::time::Instant::now();
        self.run_range(0, s0, false, "prologue")?;
        let pro_us = t_pro.elapsed().as_micros();

        // Hoist the children's constant writes. `mem_const_count` is a count, so moving these
        // earlier leaves the record identical; `timestamp` is advanced here rather than in the
        // child, which skips them.
        for &idx in program.const_write_positions() {
            let idx = idx as usize;
            if idx < s0 || idx >= e1 {
                continue;
            }
            let Instruction::Mem(mi) = &program.instructions[idx] else {
                unreachable!("const_write_positions holds only Mem instructions")
            };
            self.memory.mw(mi.addrs.inner, mi.vals.inner, mi.mult);
            self.nb_memory_ops += 1;
            self.record.mem_const_count += 1;
            self.timestamp += 1;
        }

        let hoist_us = t_pro.elapsed().as_micros() - pro_us;
        let base = Arc::new(std::mem::take(&mut self.memory.map));

        let w0: VecDeque<Block<F>> = self.witness_stream.drain(..h0).collect();
        let w1: VecDeque<Block<F>> = self.witness_stream.drain(..h1).collect();

        let t_fork = std::time::Instant::now();
        let mut c0 = self.fork(&base, w0, e0 - s0);
        let mut c1 = self.fork(&base, w1, e1 - s1);
        let fork_us = t_fork.elapsed().as_micros();
        let t_children = std::time::Instant::now();
        let plans = self.child_plans.clone();
        let (r0, r1) = std::thread::scope(|sc| {
            let t0 = sc.spawn(|| match &plans {
                Some(p) => c0.run_range_planned(&p[0], true),
                None => c0.run_range(s0, e0, true, "child0"),
            });
            let r1 = match &plans {
                Some(p) => c1.run_range_planned(&p[1], true),
                None => c1.run_range(s1, e1, true, "child1"),
            };
            // Resume the payload rather than swallow it: the default hook has already printed
            // the child's own message, and this keeps the process's exit behaviour unchanged.
            let r0 = match t0.join() {
                Ok(r) => r,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            (r0, r1)
        });
        // Child 0's error wins, and child 1's is dropped, because that is what a serial run
        // would report: serially child 1 never starts once child 0 has failed.
        if let Err(e) = r0 {
            drop(r1);
            return Err(e);
        }
        r1?;
        let children_us = t_children.elapsed().as_micros();
        let t_merge = std::time::Instant::now();

        // The children must have written disjoint addresses — see `MemVecMap::written`. Checked
        // in release too: this is the one failure that would otherwise change the record instead
        // of crashing, and it costs one comparison per node.
        // Required, not optional: an `if let` here would pass silently the day the tracking
        // stops running, which is exactly when the check is needed. A child that wrote nothing
        // is the one case with no window, and it cannot overlap anything.
        match (c0.memory.written, c1.memory.written) {
            (Some((_, hi0)), Some((lo1, _))) => assert!(
                hi0 < lo1,
                "the children's writes are not ordered: child 0 reached {hi0}, child 1 starts \
                 at {lo1}. Windows, so interleaving fails this even when no address collides — \
                 the builder's allocator is a monotone bump and does not interleave."
            ),
            (None, _) | (_, None) => assert!(
                c0.memory.map.is_empty() || c1.memory.map.is_empty(),
                "a child wrote memory without recording its address window"
            ),
        }

        // The merge tail has to see all three tables. Copying the children's back into one costs
        // more than the tail's ~8 k instructions save by having a single lookup, so keep child 1
        // as the tail's own table and read the other two through it. Disjoint by construction,
        // so which one owns `map` is arbitrary.
        c0.memory.bases = [None, None];
        c1.memory.bases = [None, None];
        self.memory.map = std::mem::take(&mut c1.memory.map);
        self.memory.bases = [
            Some(Arc::new(std::mem::take(&mut c0.memory.map))),
            Some(base),
        ];

        let fold_us = t_merge.elapsed().as_micros();

        // `Vec::append` copies its source into the destination, so appending both children into
        // the parent's record moves every event twice. Taking child 0's record whole and folding
        // the other two into it moves the largest of the three not at all: 7.2 ms -> 2.9 ms a
        // node on the reth-188 dumps.
        //
        // That puts the parent's events after child 0's, which would be out of program order —
        // except the prologue emits none: it is `init_constants`, and a constant write feeds
        // `mem_const_count` and no event vector.
        //
        // Not the guard above restated: that one reads the prologue's *shape* and declines an
        // unfamiliar one, this reads what interpreting it actually produced. A day when a
        // constant write starts emitting an event passes the first and is caught here. Kept in
        // release for the same reason as the disjointness check — reordering the record is the
        // failure that would otherwise not crash.
        assert!(
            self.record.is_position_independent(),
            "the prologue recorded something; folding it in after child 0 would reorder or drop it"
        );
        // Child 1's events are meant to come last, so only the field `append` drops applies here.
        assert!(
            c1.record
                .public_values
                .as_array()
                .iter()
                .all(|v| *v == F::ZERO),
            "child 1 set public values; `append` would drop them"
        );
        // `index` is an input rather than something emulation produces, and `merged` starts
        // from child 0's record, which was forked without it.
        let index = self.record.index;
        let mut merged = std::mem::take(&mut c0.record);
        merged.index = index;
        merged.append(&mut self.record);
        merged.append(&mut c1.record);
        merged.program = Arc::clone(&self.program);
        self.record = merged;

        // The children keep their own tallies; without this `print_stats` would report the
        // prologue and the merge tail only. `clk` is deliberately not among them: it is
        // write-only in this interpreter (assigned per instruction, read by nothing), so the
        // children restarting it at zero is invisible. Record anything derived from it and that
        // stops being true — the digest gate would catch it, nothing else would.
        for c in [&c0, &c1] {
            self.timestamp += c.timestamp;
            self.nb_poseidons += c.nb_poseidons;
            self.nb_wide_poseidons += c.nb_wide_poseidons;
            self.nb_bit_decompositions += c.nb_bit_decompositions;
            self.nb_ext_ops += c.nb_ext_ops;
            self.nb_base_ops += c.nb_base_ops;
            self.nb_memory_ops += c.nb_memory_ops;
            self.nb_branch_ops += c.nb_branch_ops;
            self.nb_select += c.nb_select;
            self.nb_exp_reverse_bits += c.nb_exp_reverse_bits;
            self.nb_batch_fri += c.nb_batch_fri;
            self.nb_print_f += c.nb_print_f;
            self.nb_print_e += c.nb_print_e;
        }
        let append_us = t_merge.elapsed().as_micros() - fold_us;

        let t_tail = std::time::Instant::now();
        self.run_range(e1, program.instructions.len(), false, "merge")?;
        // Where a split node's time goes. The two children are the only part that shrinks; every
        // other phase is overhead the serial path does not pay, so this is what says whether the
        // idea is worth its machinery.
        tracing::info!(
            target: "bench",
            "rec_emulate_split_phases: prologue_us = {pro_us}, hoist_us = {hoist_us}, \
             fork_us = {fork_us}, children_us = {children_us}, fold_us = {fold_us}, \
             append_us = {append_us}, tail_us = {}",
            t_tail.elapsed().as_micros(),
        );
        Ok(true)
    }

    /// The instruction at `pc`, then `pc`, `clk` and `timestamp` advanced: `run_range`'s loop
    /// body, so a planned run ([`Self::run_range_planned`]) can drive it in another order.
    #[inline(always)]
    fn step(
        &mut self,
        skip_const_writes: bool,
        profiling: bool,
        profile: &mut EmulateProfile,
    ) -> Result<(), RuntimeError<F, EF>> {
        let idx = self.pc.as_canonical_u32() as usize;
        let instruction = self.program.instructions[idx].clone();
        // Both reads are inside the `profiling` branch, so an unprofiled run pays one
        // predictable test per instruction and no clock.
        let sample = profiling.then(|| (instruction.kind(), profile::ticks()));
        if let Some(t) = &self.memory.depth {
            t.cur.set(0);
        }

        let next_clk = self.clk + F::from_u32(4);
        let next_pc = self.pc + F::ONE;
        if skip_const_writes && is_const_write(&instruction) {
            // Already evaluated ahead of this range, and `mw` panics on a second write.
            // `timestamp` is not advanced: the caller counted it when it ran the write.
            self.pc = next_pc;
            self.clk = next_clk;
            return Ok(());
        }
        match instruction {
            Instruction::BaseAlu(
                instr @ BaseAluInstr {
                    opcode,
                    mult,
                    addrs,
                },
            ) => {
                self.nb_base_ops += 1;
                let in1 = self.memory.mr(addrs.in1).val[0];
                let in2 = self.memory.mr(addrs.in2).val[0];
                // Do the computation.
                let out = match opcode {
                    BaseAluOpcode::AddF => in1 + in2,
                    BaseAluOpcode::SubF => in1 - in2,
                    BaseAluOpcode::MulF => in1 * in2,
                    BaseAluOpcode::DivF => match in2.try_inverse() {
                        Some(x) => in1 * x,
                        None => {
                            // Check for division exceptions and error. Note that 0/0 is defined
                            // to be 1.
                            if in1.is_zero() {
                                PrimeCharacteristicRing::ONE
                            } else {
                                return Err(RuntimeError::DivFOutOfDomain {
                                    in1,
                                    in2,
                                    instr,
                                    pc: self.pc.as_canonical_u32() as usize,
                                    trace: self.nearest_pc_backtrace(),
                                });
                            }
                        }
                    },
                };
                self.memory.mw(addrs.out, Block::from(out), mult);
                self.record
                    .base_alu_events
                    .push(BaseAluEvent { out, in1, in2 });
            }
            Instruction::ExtAlu(
                instr @ ExtAluInstr {
                    opcode,
                    mult,
                    addrs,
                },
            ) => {
                self.nb_ext_ops += 1;
                let in1 = self.memory.mr(addrs.in1).val;
                let in2 = self.memory.mr(addrs.in2).val;
                // Do the computation.
                let in1_ef = EF::from_basis_coefficients_slice(&in1.0)
                    .expect("a Block holds EXTENSION_DEGREE coefficients");
                let in2_ef = EF::from_basis_coefficients_slice(&in2.0)
                    .expect("a Block holds EXTENSION_DEGREE coefficients");
                let out_ef = match opcode {
                    ExtAluOpcode::AddE => in1_ef + in2_ef,
                    ExtAluOpcode::SubE => in1_ef - in2_ef,
                    ExtAluOpcode::MulE => in1_ef * in2_ef,
                    ExtAluOpcode::DivE => match in2_ef.try_inverse() {
                        Some(x) => in1_ef * x,
                        None => {
                            // Check for division exceptions and error. Note that 0/0 is defined
                            // to be 1.
                            if in1_ef.is_zero() {
                                PrimeCharacteristicRing::ONE
                            } else {
                                return Err(RuntimeError::DivEOutOfDomain {
                                    in1: in1_ef,
                                    in2: in2_ef,
                                    instr,
                                    pc: self.pc.as_canonical_u32() as usize,
                                    trace: self.nearest_pc_backtrace(),
                                });
                            }
                        }
                    },
                };
                let out = Block::from(out_ef.as_basis_coefficients_slice());
                self.memory.mw(addrs.out, out, mult);
                self.record
                    .ext_alu_events
                    .push(ExtAluEvent { out, in1, in2 });
            }
            Instruction::Mem(MemInstr {
                addrs: MemIo { inner: addr },
                vals: MemIo { inner: val },
                mult,
                kind,
            }) => {
                self.nb_memory_ops += 1;
                match kind {
                    MemAccessKind::Read => {
                        let mem_entry = self.memory.mr(addr);
                        assert_eq!(
                            mem_entry.val, val,
                            "stored memory value should be the specified value"
                        );
                    }
                    MemAccessKind::Write => drop(self.memory.mw(addr, val, mult)),
                }
                self.record.mem_const_count += 1;
            }
            Instruction::Poseidon2(instr) => {
                let Poseidon2Instr {
                    addrs: Poseidon2Io { input, output },
                    mults,
                } = *instr;
                self.nb_poseidons += 1;
                let in_vals = std::array::from_fn(|i| self.memory.mr(input[i]).val[0]);
                let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                perm_output
                    .iter()
                    .zip(output)
                    .zip(mults)
                    .for_each(|((&val, addr), mult)| {
                        self.memory.mw(addr, Block::from(val), mult);
                    });
                self.record.poseidon2_events.push(Poseidon2Event {
                    input: in_vals,
                    output: perm_output,
                });
            }
            Instruction::Select(SelectInstr {
                addrs:
                    SelectIo {
                        bit,
                        out1,
                        out2,
                        in1,
                        in2,
                    },
                mult1,
                mult2,
            }) => {
                self.nb_select += 1;
                let bit = self.memory.mr(bit).val[0];
                let in1 = self.memory.mr(in1).val[0];
                let in2 = self.memory.mr(in2).val[0];
                let out1_val = bit * in2 + (F::ONE - bit) * in1;
                let out2_val = bit * in1 + (F::ONE - bit) * in2;
                self.memory.mw(out1, Block::from(out1_val), mult1);
                self.memory.mw(out2, Block::from(out2_val), mult2);
                self.record.select_events.push(SelectEvent {
                    bit,
                    out1: out1_val,
                    out2: out2_val,
                    in1,
                    in2,
                })
            }
            Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
                addrs: ExpReverseBitsIo { base, exp, result },
                mult,
            }) => {
                self.nb_exp_reverse_bits += 1;
                let base_val = self.memory.mr(base).val[0];
                let exp_bits: Vec<_> = exp.iter().map(|bit| self.memory.mr(*bit).val[0]).collect();
                let exp_val = exp_bits
                    .iter()
                    .enumerate()
                    .fold(0, |acc, (i, &val)| acc + val.as_canonical_u32() * (1 << i));
                let out =
                    base_val.exp_u64(reverse_bits_len(exp_val as usize, exp_bits.len()) as u64);
                self.memory.mw(result, Block::from(out), mult);
                self.record
                    .exp_reverse_bits_len_events
                    .push(ExpReverseBitsEvent {
                        result: out,
                        base: base_val,
                        exp: exp_bits,
                    });
            }
            Instruction::HintBits(HintBitsInstr {
                output_addrs_mults,
                input_addr,
            }) => {
                self.nb_bit_decompositions += 1;
                let num = self.memory.mr(input_addr).val[0].as_canonical_u32();
                // Decompose the num into LE bits.
                let bits = (0..output_addrs_mults.len())
                    .map(|i| Block::from(F::from_u32((num >> i) & 1)))
                    .collect::<Vec<_>>();
                // Write the bits to the array at dst.
                for (bit, (addr, mult)) in bits.into_iter().zip(output_addrs_mults) {
                    self.memory.mw(addr, bit, mult);
                    self.record.mem_var_events.push(MemEvent { inner: bit });
                }
            }

            Instruction::BatchFRI(instr) => {
                let BatchFRIInstr {
                    base_vec_addrs,
                    ext_single_addrs,
                    ext_vec_addrs,
                    acc_mult,
                } = *instr;

                let mut acc = EF::ZERO;
                let p_at_xs = base_vec_addrs
                    .p_at_x
                    .iter()
                    .map(|addr| self.memory.mr(*addr).val[0])
                    .collect_vec();
                let p_at_zs = ext_vec_addrs
                    .p_at_z
                    .iter()
                    .map(|addr| self.memory.mr(*addr).val.ext::<EF>())
                    .collect_vec();
                let alpha_pows: Vec<_> = ext_vec_addrs
                    .alpha_pow
                    .iter()
                    .map(|addr| self.memory.mr(*addr).val.ext::<EF>())
                    .collect_vec();

                self.nb_batch_fri += p_at_zs.len();
                for m in 0..p_at_zs.len() {
                    acc += alpha_pows[m] * (p_at_zs[m] - EF::from(p_at_xs[m]));
                    self.record.batch_fri_events.push(BatchFRIEvent {
                        base_vec: BatchFRIBaseVecIo { p_at_x: p_at_xs[m] },
                        ext_single: BatchFRIExtSingleIo {
                            acc: Block::from(acc.as_basis_coefficients_slice()),
                        },
                        ext_vec: BatchFRIExtVecIo {
                            p_at_z: Block::from(p_at_zs[m].as_basis_coefficients_slice()),
                            alpha_pow: Block::from(alpha_pows[m].as_basis_coefficients_slice()),
                        },
                    });
                }

                let _ = self.memory.mw(
                    ext_single_addrs.acc,
                    Block::from(acc.as_basis_coefficients_slice()),
                    acc_mult,
                );
            }

            Instruction::CommitPublicValues(instr) => {
                let pv_addrs = instr.pv_addrs.as_array();
                let pv_values: [F; RECURSION_NUM_PVS] =
                    array::from_fn(|i| self.memory.mr(pv_addrs[i]).val[0]);
                self.record.public_values = *pv_values.as_slice().borrow();
                self.record
                    .commit_pv_hash_events
                    .push(CommitPublicValuesEvent {
                        public_values: self.record.public_values,
                    });
            }

            Instruction::HintAddCurve(instr) => {
                let HintAddCurveInstr {
                    output_x_addrs_mults,
                    output_y_addrs_mults,
                    input1_x_addrs,
                    input1_y_addrs,
                    input2_x_addrs,
                    input2_y_addrs,
                } = *instr;
                let input1_x = SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                    self.memory.mr(input1_x_addrs[i]).val[0]
                });
                let input1_y = SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                    self.memory.mr(input1_y_addrs[i]).val[0]
                });
                let input2_x = SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                    self.memory.mr(input2_x_addrs[i]).val[0]
                });
                let input2_y = SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                    self.memory.mr(input2_y_addrs[i]).val[0]
                });
                let point1 = SepticCurve {
                    x: input1_x,
                    y: input1_y,
                };
                let point2 = SepticCurve {
                    x: input2_x,
                    y: input2_y,
                };
                let output = point1.add_incomplete(point2);

                for (val, (addr, mult)) in output.x.0.into_iter().zip(output_x_addrs_mults) {
                    self.memory.mw(addr, Block::from(val), mult);
                    self.record.mem_var_events.push(MemEvent {
                        inner: Block::from(val),
                    });
                }
                for (val, (addr, mult)) in output.y.0.into_iter().zip(output_y_addrs_mults) {
                    self.memory.mw(addr, Block::from(val), mult);
                    self.record.mem_var_events.push(MemEvent {
                        inner: Block::from(val),
                    });
                }
            }

            Instruction::Print(PrintInstr {
                field_elt_type,
                addr,
            }) => match field_elt_type {
                FieldEltType::Base => {
                    self.nb_print_f += 1;
                    let f = self.memory.mr(addr).val[0];
                    writeln!(self.debug_stdout, "PRINTF={f}")
                }
                FieldEltType::Extension => {
                    self.nb_print_e += 1;
                    let ef = self.memory.mr(addr).val;
                    writeln!(self.debug_stdout, "PRINTEF={ef:?}")
                }
            }
            .map_err(RuntimeError::DebugPrint)?,
            Instruction::HintExt2Felts(HintExt2FeltsInstr {
                output_addrs_mults,
                input_addr,
            }) => {
                self.nb_bit_decompositions += 1;
                let fs = self.memory.mr(input_addr).val;
                // Write the bits to the array at dst.
                for (f, (addr, mult)) in fs.into_iter().zip(output_addrs_mults) {
                    let felt = Block::from(f);
                    self.memory.mw(addr, felt, mult);
                    self.record.mem_var_events.push(MemEvent { inner: felt });
                }
            }
            Instruction::Hint(HintInstr { output_addrs_mults }) => {
                // Check that enough Blocks can be read, so `drain` does not panic.
                if self.witness_stream.len() < output_addrs_mults.len() {
                    return Err(RuntimeError::EmptyWitnessStream);
                }
                let witness = self.witness_stream.drain(0..output_addrs_mults.len());
                for ((addr, mult), val) in zip(output_addrs_mults, witness) {
                    // Inline [`Self::mw`] to mutably borrow multiple fields of `self`.
                    self.memory.mw(addr, val, mult);
                    self.record.mem_var_events.push(MemEvent { inner: val });
                }
            }
            Instruction::AssertZeroExt(AssertZeroExtInstr { addr }) => {
                let val = self.memory.mr(addr).val;
                debug_assert!(
                    val.ext::<EF>() == EF::ZERO,
                    "AssertZeroExt: expected zero at addr {:?}, got {:?}",
                    addr,
                    val
                );
                self.record
                    .assert_zero_ext_events
                    .push(AssertZeroExtEvent { val });
            }
            Instruction::FracFold(FracFoldInstr {
                in_p1_addr,
                in_q1_addr,
                in_p2_addr,
                in_q2_addr,
                out_p_addr,
                out_q_addr,
                mult,
            }) => {
                let p1 = self.memory.mr(in_p1_addr).val;
                let q1 = self.memory.mr(in_q1_addr).val;
                let p2 = self.memory.mr(in_p2_addr).val;
                let q2 = self.memory.mr(in_q2_addr).val;
                let p1_ef = p1.ext::<EF>();
                let q1_ef = q1.ext::<EF>();
                let p2_ef = p2.ext::<EF>();
                let q2_ef = q2.ext::<EF>();
                let out_p =
                    Block::from((p1_ef * q2_ef + p2_ef * q1_ef).as_basis_coefficients_slice());
                let out_q = Block::from((q1_ef * q2_ef).as_basis_coefficients_slice());
                self.memory.mw(out_p_addr, out_p, mult);
                self.memory.mw(out_q_addr, out_q, mult);
                self.record.frac_fold_events.push(FracFoldEvent {
                    p1,
                    q1,
                    p2,
                    q2,
                    out_p,
                    out_q,
                });
            }
            Instruction::UnivariateFold(box_instr) => {
                let UnivariateFoldInstr {
                    coeffs_addrs,
                    claimed_sum_addr,
                    r_addr,
                    next_sum_addr,
                    mult,
                } = *box_instr;
                let coeffs: Vec<Block<F>> = coeffs_addrs
                    .iter()
                    .map(|&addr| self.memory.mr(addr).val)
                    .collect();
                let claimed_sum = self.memory.mr(claimed_sum_addr).val;
                let r = self.memory.mr(r_addr).val;
                let r_ef = r.ext::<EF>();
                let n = coeffs.len();
                let mut horner = coeffs[n - 1].ext::<EF>();
                for coeff in coeffs[..n - 1].iter().rev() {
                    horner = r_ef * horner + coeff.ext::<EF>();
                }
                let next_sum = Block::from(horner.as_basis_coefficients_slice());
                self.memory.mw(next_sum_addr, next_sum, mult);
                self.record
                    .univariate_fold_events
                    .push(UnivariateFoldEvent {
                        coeffs,
                        claimed_sum,
                        r,
                        next_sum,
                    });
            }
            Instruction::LagrangeEvalD2(LagrangeEvalD2Instr {
                claim_addr,
                s1_addr,
                s2_addr,
                r_addr,
                next_claim_addr,
                mult,
            }) => {
                let claim = self.memory.mr(claim_addr).val;
                let s1 = self.memory.mr(s1_addr).val;
                let s2 = self.memory.mr(s2_addr).val;
                let r = self.memory.mr(r_addr).val;
                let claim_ef = claim.ext::<EF>();
                let s1_ef = s1.ext::<EF>();
                let s2_ef = s2.ext::<EF>();
                let r_ef = r.ext::<EF>();
                // p(r) with p(0) = claim - s1, p(1) = s1, p(2) = s2:
                //   p(r) = (s0*(r-1)*(r-2) - 2*s1*r*(r-2) + s2*r*(r-1)) / 2
                let s0_ef = claim_ef - s1_ef;
                let one = EF::ONE;
                let two = EF::TWO;
                let num = s0_ef * (r_ef - one) * (r_ef - two) - two * s1_ef * r_ef * (r_ef - two)
                    + s2_ef * r_ef * (r_ef - one);
                let next_ef = num * two.inverse();
                let next_claim = Block::from(next_ef.as_basis_coefficients_slice());
                self.memory.mw(next_claim_addr, next_claim, mult);
                self.record
                    .lagrange_eval_d2_events
                    .push(LagrangeEvalD2Event {
                        claim,
                        s1,
                        s2,
                        r,
                        next_claim,
                    });
            }
            Instruction::GkrSumcheckRound(box_instr) => {
                let GkrSumcheckRoundInstr {
                    claim_addr,
                    s1_addr,
                    s2_addr,
                    s3_addr,
                    r_addr,
                    xi_addr,
                    eq_in_addr,
                    next_claim_addr,
                    eq_out_addr,
                    mult_next,
                    mult_eq,
                } = *box_instr;
                let claim = self.memory.mr(claim_addr).val;
                let s1 = self.memory.mr(s1_addr).val;
                let s2 = self.memory.mr(s2_addr).val;
                let s3 = self.memory.mr(s3_addr).val;
                let r = self.memory.mr(r_addr).val;
                let xi = self.memory.mr(xi_addr).val;
                let eq_in = self.memory.mr(eq_in_addr).val;
                let claim_ef = claim.ext::<EF>();
                let s1_ef = s1.ext::<EF>();
                let s2_ef = s2.ext::<EF>();
                let s3_ef = s3.ext::<EF>();
                let r_ef = r.ext::<EF>();
                let xi_ef = xi.ext::<EF>();
                let eq_in_ef = eq_in.ext::<EF>();
                // p(r) with p(0) = claim - s1, p(1) = s1, p(2) = s2, p(3) = s3:
                //   6*p(r) = -s0*(r-1)(r-2)(r-3) + 3*s1*r(r-2)(r-3)
                //            - 3*s2*r(r-1)(r-3) + s3*r(r-1)(r-2)
                let s0_ef = claim_ef - s1_ef;
                let one = EF::ONE;
                let two = EF::TWO;
                let three = EF::from_u32(3);
                let six = EF::from_u32(6);
                let a = (r_ef - one) * (r_ef - two) * (r_ef - three);
                let b = r_ef * (r_ef - two) * (r_ef - three);
                let c = r_ef * (r_ef - one) * (r_ef - three);
                let d = r_ef * (r_ef - one) * (r_ef - two);
                let num = three * s1_ef * b + s3_ef * d - s0_ef * a - three * s2_ef * c;
                let next_ef = num * six.inverse();
                // eq_out = eq_in * (2*xi*r - xi - r + 1)
                let eq_factor = two * xi_ef * r_ef - xi_ef - r_ef + one;
                let eq_out_ef = eq_in_ef * eq_factor;
                let next_claim = Block::from(next_ef.as_basis_coefficients_slice());
                let eq_out = Block::from(eq_out_ef.as_basis_coefficients_slice());
                self.memory.mw(next_claim_addr, next_claim, mult_next);
                self.memory.mw(eq_out_addr, eq_out, mult_eq);
                self.record
                    .gkr_sumcheck_round_events
                    .push(GkrSumcheckRoundEvent {
                        claim,
                        s1,
                        s2,
                        s3,
                        r,
                        xi,
                        eq_in,
                        next_claim,
                        eq_out,
                    });
            }
            Instruction::ExtDotProduct(box_instr) => {
                let ExtDotProductInstr {
                    mu_addrs,
                    val_addrs,
                    acc_addr,
                    mult,
                } = *box_instr;
                debug_assert_eq!(mu_addrs.len(), PACK_LANES * val_addrs.len());
                debug_assert_eq!(val_addrs.len() % EXT_DOT_PRODUCT_GROUPS, 0);
                let mut acc = EF::ZERO;
                for (val_chunk, mu_chunk) in val_addrs
                    .as_chunks::<EXT_DOT_PRODUCT_GROUPS>()
                    .0
                    .iter()
                    .zip(mu_addrs.as_chunks::<EXT_DOT_PRODUCT_DATAPAR>().0)
                {
                    // Each value block is packed: only its first PACK_LANES lanes carry
                    // values (the chip reads it with `looked_packed`).
                    let vals: [[F; PACK_LANES]; EXT_DOT_PRODUCT_GROUPS] =
                        std::array::from_fn(|g| {
                            let block = self.memory.mr(val_chunk[g]).val;
                            std::array::from_fn(|k| block.0[k])
                        });
                    let mus: [Block<F>; EXT_DOT_PRODUCT_DATAPAR] =
                        std::array::from_fn(|j| self.memory.mr(mu_chunk[j]).val);
                    for g in 0..EXT_DOT_PRODUCT_GROUPS {
                        for k in 0..PACK_LANES {
                            acc += mus[g * PACK_LANES + k].ext::<EF>() * EF::from(vals[g][k]);
                        }
                    }
                    self.record.ext_dot_product_events.push(ExtDotProductEvent {
                        mus,
                        vals,
                        acc: Block::from(acc.as_basis_coefficients_slice()),
                    });
                }
                self.memory.mw(
                    acc_addr,
                    Block::from(acc.as_basis_coefficients_slice()),
                    mult,
                );
            }
            Instruction::HornerEval(box_instr) => {
                let HornerEvalInstr {
                    coeff_addrs,
                    x_addr,
                    out_addr,
                    mult,
                } = *box_instr;
                let x = self.memory.mr(x_addr).val;
                let x_ef = x.ext::<EF>();
                let mut acc = EF::ZERO;
                debug_assert_eq!(coeff_addrs.len() % HORNER_EVAL_DATAPAR, 0);
                // coeff_addrs are in evaluation order (highest degree first,
                // front-padded with zero addresses to a DATAPAR multiple).
                for chunk in coeff_addrs.as_chunks::<HORNER_EVAL_DATAPAR>().0 {
                    let coeffs: [Block<F>; HORNER_EVAL_DATAPAR] =
                        std::array::from_fn(|j| self.memory.mr(chunk[j]).val);
                    for c in &coeffs {
                        acc = acc * x_ef + c.ext::<EF>();
                    }
                    self.record.horner_eval_events.push(HornerEvalEvent {
                        coeffs,
                        x,
                        acc: Block::from(acc.as_basis_coefficients_slice()),
                    });
                }
                self.memory.mw(
                    out_addr,
                    Block::from(acc.as_basis_coefficients_slice()),
                    mult,
                );
            }
            Instruction::DigestSelect(box_instr) => {
                let DigestSelectInstr {
                    bit_addr,
                    in1_addrs,
                    in2_addrs,
                    out_addrs,
                    mults,
                } = *box_instr;
                let bit = self.memory.mr(bit_addr).val[0];
                let in1b: [Block<F>; DIGEST_BLOCKS] =
                    std::array::from_fn(|j| self.memory.mr(in1_addrs[j]).val);
                let in2b: [Block<F>; DIGEST_BLOCKS] =
                    std::array::from_fn(|j| self.memory.mr(in2_addrs[j]).val);
                let in1: [F; DIGEST_SIZE] =
                    std::array::from_fn(|i| in1b[i / PACK_LANES].0[i % PACK_LANES]);
                let in2: [F; DIGEST_SIZE] =
                    std::array::from_fn(|i| in2b[i / PACK_LANES].0[i % PACK_LANES]);
                let out: [F; DIGEST_SIZE] =
                    std::array::from_fn(|i| bit * in2[i] + (F::ONE - bit) * in1[i]);
                for j in 0..DIGEST_BLOCKS {
                    let blk = Block::packed(std::array::from_fn(|k| out[PACK_LANES * j + k]));
                    self.memory.mw(out_addrs[j], blk, mults[j]);
                }
                self.record
                    .digest_select_events
                    .push(DigestSelectEvent { bit, in1, in2, out });
            }
            Instruction::BinaryFoldStep(box_instr) => {
                let BinaryFoldStepInstr {
                    tw_addr,
                    xi_addr,
                    inv_tw_addr,
                    xi_inv_addr,
                    alpha_addr,
                    v_lo_addr,
                    v_hi_addr,
                    out_addr,
                    mult,
                } = *box_instr;
                let tw = self.memory.mr(tw_addr).val[0];
                let xi = self.memory.mr(xi_addr).val[0];
                let inv_tw = self.memory.mr(inv_tw_addr).val[0];
                let xi_inv = self.memory.mr(xi_inv_addr).val[0];
                let alpha = self.memory.mr(alpha_addr).val;
                let v_lo = self.memory.mr(v_lo_addr).val;
                let v_hi = self.memory.mr(v_hi_addr).val;
                let alpha_ef = alpha.ext::<EF>();
                let v_lo_ef = v_lo.ext::<EF>();
                let v_hi_ef = v_hi.ext::<EF>();
                // out = v_lo + (alpha - tw*xi) * (v_lo - v_hi) * (inv_tw * xi_inv / 2)
                let amt = alpha_ef - EF::from(tw * xi);
                let tih = inv_tw * xi_inv * F::TWO.inverse();
                let out_ef = v_lo_ef + amt * (v_lo_ef - v_hi_ef) * EF::from(tih);
                let out = Block::from(out_ef.as_basis_coefficients_slice());
                self.memory.mw(out_addr, out, mult);
                self.record
                    .binary_fold_step_events
                    .push(BinaryFoldStepEvent {
                        tw,
                        xi,
                        inv_tw,
                        xi_inv,
                        alpha,
                        v_lo,
                        v_hi,
                        out,
                    });
            }
            Instruction::PackBlock(box_instr) => {
                let PackBlockInstr {
                    in_addrs,
                    out_addr,
                    mult,
                } = *box_instr;
                let lanes: [F; PACK_LANES] =
                    std::array::from_fn(|i| self.memory.mr(in_addrs[i]).val[0]);
                self.memory.mw(out_addr, Block::packed(lanes), mult);
                self.record.pack_block_events.push(PackBlockEvent { lanes });
            }
            Instruction::UnpackBlock(box_instr) => {
                let UnpackBlockInstr {
                    in_addr,
                    out_addrs,
                    mults,
                } = *box_instr;
                let val = self.memory.mr(in_addr).val;
                for i in 0..EXTENSION_DEGREE {
                    self.memory
                        .mw(out_addrs[i], Block::from(val.0[i]), mults[i]);
                }
                self.record
                    .unpack_block_events
                    .push(UnpackBlockEvent { val });
            }
            Instruction::Poseidon2Packed(box_instr) => {
                let Poseidon2PackedInstr {
                    input_addrs,
                    output_addrs,
                    mults,
                } = *box_instr;
                self.nb_poseidons += 1;
                let in_blocks: [Block<F>; PERM_BLOCKS] =
                    std::array::from_fn(|j| self.memory.mr(input_addrs[j]).val);
                let in_vals: [F; PERMUTATION_WIDTH] =
                    std::array::from_fn(|i| in_blocks[i / PACK_LANES].0[i % PACK_LANES]);
                let perm_output = self.perm.as_ref().unwrap().permute(in_vals);

                for j in 0..PERM_BLOCKS {
                    let out_block =
                        Block::packed(std::array::from_fn(|k| perm_output[PACK_LANES * j + k]));
                    self.memory.mw(output_addrs[j], out_block, mults[j]);
                }
                self.record.poseidon2_packed_events.push(Poseidon2Event {
                    input: in_vals,
                    output: perm_output,
                });
            }
            Instruction::MleOpen(MleOpenInstr {
                col_ref,
                opening_value_addr,
            }) => {
                let opening_value = self.memory.mr(opening_value_addr).val;
                self.record.mle_open_events.push(MleOpenEvent {
                    col_ref,
                    opening_value,
                });
            }
            Instruction::ExpBitsLen(box_instr) => {
                let ExpBitsLenInstr {
                    base,
                    num_bits,
                    bit_src_in_addr,
                    result_out_addr,
                    result_mult,
                    bit_outs_addrs_mults,
                } = *box_instr;

                // Read the field element to decompose.
                let bit_src = self.memory.mr(bit_src_in_addr).val[0];
                let decomp = bit_src.as_canonical_u32();
                let n = num_bits as usize;

                // result = base^(canonical(bit_src) mod 2^num_bits).
                let mask = if n >= 32 { u32::MAX } else { (1u32 << n) - 1 };
                let result = base.exp_u64((decomp & mask) as u64);

                // Write the result (first-row write) and the per-bit outputs (LSB-first).
                self.memory
                    .mw(result_out_addr, Block::from(result), result_mult);
                for (j, (addr, mult)) in bit_outs_addrs_mults.iter().enumerate() {
                    let bit = F::from_u32((decomp >> j) & 1);
                    self.memory.mw(*addr, Block::from(bit), *mult);
                }

                self.record.exp_bits_len_events.push(ExpBitsLenEvent {
                    base,
                    bit_src,
                    num_bits,
                });
            }
        }

        if let Some((kind, t0)) = sample {
            profile.add(kind, profile::ticks().wrapping_sub(t0));
        }
        if let Some(t) = &self.memory.depth {
            self.depth_log.push(t.cur.get() + 1);
        }

        self.pc = next_pc;
        self.clk = next_clk;
        self.timestamp += 1;
        Ok(())
    }

    /// The lengths of every event vector, in `record_event_vecs!` order.
    fn event_lens(&self) -> [usize; RECORD_EVENT_VECS] {
        // Exhaustive, like `RecursionRecord::digest`: the fields left out are not per-instruction
        // event lists, and their values do not depend on the order instructions run in.
        macro_rules! lens {
            ($($v:ident),*) => {{
                let RecursionRecord {
                    program: _,
                    index: _,
                    mem_const_count: _,
                    public_values: _,
                    $($v),*
                } = &self.record;
                [$($v.len()),*]
            }};
        }
        record_event_vecs!(lens)
    }

    /// `Poseidon2Packed` for every instruction in `idxs` at once (they are independent): read
    /// every input, permute all the states through `batch_perm`, then write and record in `idxs`
    /// order.
    fn poseidon2_packed_batch(&mut self, program: &RecursionProgram<F>, idxs: &[u32]) {
        let mut states: Vec<[F; PERMUTATION_WIDTH]> = idxs
            .iter()
            .map(|&idx| {
                let Instruction::Poseidon2Packed(instr) = &program.instructions[idx as usize]
                else {
                    unreachable!("batched a non-Poseidon2Packed instruction")
                };
                let in_blocks: [Block<F>; PERM_BLOCKS] =
                    std::array::from_fn(|j| self.memory.mr(instr.input_addrs[j]).val);
                std::array::from_fn(|i| in_blocks[i / PACK_LANES].0[i % PACK_LANES])
            })
            .collect();
        let inputs = states.clone();
        match &self.batch_perm {
            Some(f) => f(&mut states),
            None => {
                let perm = self.perm.as_ref().unwrap();
                for s in states.iter_mut() {
                    *s = perm.permute(*s);
                }
            }
        }
        for ((&idx, input), output) in idxs.iter().zip(inputs).zip(states) {
            let Instruction::Poseidon2Packed(instr) = &program.instructions[idx as usize] else {
                unreachable!()
            };
            for j in 0..PERM_BLOCKS {
                let out_block = Block::packed(std::array::from_fn(|k| output[PACK_LANES * j + k]));
                self.memory
                    .mw(instr.output_addrs[j], out_block, instr.mults[j]);
            }
            self.record
                .poseidon2_packed_events
                .push(Poseidon2Event { input, output });
            self.nb_poseidons += 1;
            self.timestamp += 1;
        }
    }

    /// One in-order run of the whole program with depth tracking and event counting on, the
    /// input to [`WavefrontPlan::new`]. Returns each instruction's depth and, for every
    /// instruction that pushes events, `(instruction, event vector, count)`. The record is
    /// `run()`'s.
    #[allow(clippy::type_complexity)]
    pub fn census(&mut self) -> Result<(Vec<u32>, Vec<(u32, u8, u32)>), RuntimeError<F, EF>> {
        self.memory.depth = Some(DepthTrack::default());
        let mut profile = EmulateProfile::default();
        let mut entries = Vec::new();
        self.pc = F::ZERO;
        let n = self.program.instructions.len();
        while self.pc < F::from_u32(n as u32) {
            let idx = self.pc.as_canonical_u32();
            let before = self.event_lens();
            self.step(false, false, &mut profile)?;
            let after = self.event_lens();
            for k in 0..RECORD_EVENT_VECS {
                if after[k] > before[k] {
                    entries.push((idx, k as u8, (after[k] - before[k]) as u32));
                }
            }
        }
        self.memory.depth = None;
        Ok((std::mem::take(&mut self.depth_log), entries))
    }

    /// Interpret the instructions of `plan` in its order, each level's `Poseidon2Packed` ones as
    /// one batch, then move every event this call pushed to its program-order slot.
    ///
    /// The record is `run_range`'s: memory is written once, so any order that respects the data
    /// dependencies computes the same values, and the instructions that read nothing (`Hint`, the
    /// only one that drains the witness stream, among them) are at depth 1 and run first in each
    /// window in program order, so the stream still drains in program order.
    pub fn run_range_planned(
        &mut self,
        plan: &WavefrontPlan,
        skip_const_writes: bool,
    ) -> Result<(), RuntimeError<F, EF>> {
        let program = Arc::clone(&self.program);
        let start = self.event_lens();
        let mut profile = EmulateProfile::default();
        for &(a, m, b) in &plan.levels {
            for &idx in &plan.order[a as usize..m as usize] {
                self.pc = F::from_u32(idx);
                self.step(skip_const_writes, false, &mut profile)?;
            }
            if m < b {
                self.poseidon2_packed_batch(&program, &plan.order[m as usize..b as usize]);
            }
        }
        let mut k = 0;
        macro_rules! place {
            ($($v:ident),*) => {$(
                let tail = self.record.$v.split_off(start[k]);
                let dest = &plan.dest[k];
                assert_eq!(dest.len(), tail.len(), "planned run pushed a different event count");
                let mut slots: Vec<Option<_>> = (0..tail.len()).map(|_| None).collect();
                for (e, &d) in tail.into_iter().zip(dest) {
                    slots[d as usize] = Some(e);
                }
                self.record.$v.extend(slots.into_iter().map(|e| e.unwrap()));
                k += 1;
            )*};
        }
        record_event_vecs!(place);
        let _ = k;
        Ok(())
    }

    /// Interpret `instructions[from..to]`.
    ///
    /// `skip_const_writes` leaves `Instruction::Mem(Write)` alone, for a range whose constants a
    /// caller has already evaluated ahead of it — see [`Self::run_split`]. `phase` names the range
    /// on the measurement lines so a split run's four ranges stay apart.
    pub fn run_range(
        &mut self,
        from: usize,
        to: usize,
        skip_const_writes: bool,
        phase: &str,
    ) -> Result<(), RuntimeError<F, EF>> {
        self.pc = F::from_u32(from as u32);
        let early_exit_ts = std::env::var("RECURSION_EARLY_EXIT_TS")
            .map_or(usize::MAX, |ts: String| ts.parse().unwrap());
        let profiling = *profile::PROFILE;
        let mut profile = EmulateProfile::default();
        while self.pc < F::from_u32(to as u32) {
            self.step(skip_const_writes, profiling, &mut profile)?;

            if self.timestamp >= early_exit_ts {
                break;
            }
        }
        if profiling {
            profile.report(
                &format!("{}/{phase}", self.dump_label),
                to - from,
                self.program.total_memory,
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;
    use crate::{
        compiler::recursion::{
            instruction::{base_alu, ext_alu, mem},
            types::{Address, MemAccessKind},
        },
        primitives::consts::KOALABEAR_S_BOX_DEGREE,
    };
    use p3_koala_bear::KoalaBear;
    use pico_mle_core::config::koala_bear_poseidon2::{default_koalabear_poseidon2_16, EF};

    type Kb = KoalaBear;

    /// prologue | child 0 | child 1 | merge, in miniature — and deliberately not the simplest
    /// program of that shape.
    ///
    /// A first version used only `BaseAlu` chains, and a reviewer showed it was worthless: with
    /// no `Mem(Write)` inside the child ranges, deleting the whole constant hoist left it
    /// passing, and with no `Hint`, so did swapping the two children's slices of the witness
    /// stream. It read as coverage without being any. This one exercises each mechanism:
    ///
    /// - `idx 3` writes a constant **inside child 0** that **child 1 reads** — the case
    ///   `const_f` produces in the real circuit, which is why the hoist exists at all.
    ///   Without the hoist, child 1 reads an address only child 0's private table holds.
    /// - both children read one `Hint`, so a mis-split witness stream gives them each other's
    ///   value and changes the record.
    /// - both children emit into two event vectors, not one, so the concatenation is exercised
    ///   in more than a single lane.
    /// - the merge tail reads from child 0 (`bases[0]`), child 1 (`map`) and the prologue
    ///   (`bases[1]`), so all three levels of the fall-through are on the path.
    fn tiny_split_program() -> RecursionProgram<Kb> {
        let (add, mul) = (BaseAluOpcode::AddF, BaseAluOpcode::MulF);
        let eadd = ExtAluOpcode::AddE;
        let hint = |addr: u32| {
            Instruction::Hint(HintInstr {
                output_addrs_mults: vec![(Address(Kb::from_u32(addr)), Kb::ONE)],
            })
        };
        // Addresses climb with the instructions, as the builder's bump allocator makes them.
        let instructions = vec![
            // prologue: 0, 1
            mem(MemAccessKind::Write, 4, 0, 7),
            mem(MemAccessKind::Write, 3, 1, 11),
            // child 0: 2, 4, 5, 6, 7  (3 is hoisted out of it)
            base_alu(add, 1, 2, 0, 1),
            mem(MemAccessKind::Write, 2, 3, 5),
            hint(4),
            base_alu(mul, 1, 5, 2, 4),
            ext_alu(eadd, 1, 6, 5, 3),
            base_alu(add, 2, 7, 5, 1),
            // child 1: 8, 9, 10, 11, 12
            base_alu(add, 1, 8, 0, 3),
            hint(9),
            base_alu(mul, 1, 10, 8, 9),
            ext_alu(eadd, 1, 11, 10, 8),
            base_alu(add, 2, 12, 10, 1),
            // merge: reads child 0 (7), child 1 (12) and the prologue (0)
            base_alu(add, 1, 13, 7, 12),
            base_alu(add, 0, 14, 13, 0),
        ];
        RecursionProgram {
            instructions,
            total_memory: 15,
            child_spans: vec![(2, 8), (8, 13)],
            ..Default::default()
        }
    }

    /// The witness-length guard is not a span shape, so it gets its own test rather than a row
    /// in the table above: a stream too short for both children must decline and still run.
    #[test]
    fn split_declines_a_witness_stream_too_short_for_both_children() {
        let program = Arc::new(tiny_split_program());
        let mut rt = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
            Arc::clone(&program),
            default_koalabear_poseidon2_16(),
        );
        // One block where the two children want one each.
        rt.witness_stream = VecDeque::from(vec![Block::from(Kb::from_u32(101))]);
        // Serially this is `EmptyWitnessStream` at the second hint; the point is that it gets
        // there at all rather than panicking in `drain` before the program runs.
        assert!(
            rt.run_split().is_err(),
            "a short stream should fail, not split"
        );
    }

    /// Two blocks, distinguishable, so a witness stream handed to the wrong child shows up.
    fn witness() -> VecDeque<Block<Kb>> {
        VecDeque::from(vec![
            Block::from(Kb::from_u32(101)),
            Block::from(Kb::from_u32(202)),
        ])
    }

    /// The gate the whole split rests on: interpreting the two children concurrently must produce
    /// the record that interpreting them in order produces.
    ///
    /// Here rather than only in `rec-emulate-replay`, which needs a dumped node and someone to
    /// remember to run it. ⚠️ CI does not run this test, so it is a gate for whoever runs
    /// `cargo test`, not an automatic one.
    #[test]
    fn split_and_serial_produce_the_same_record() {
        let program = Arc::new(tiny_split_program());

        let mut serial = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
            Arc::clone(&program),
            default_koalabear_poseidon2_16(),
        );
        serial.witness_stream = witness();
        // `index` is an input rather than something emulation produces, and the merged record
        // starts from child 0's, which was forked without it. Set on both so the merge has to
        // carry it rather than inherit the fork's default.
        serial.record.index = 7;
        serial.run().expect("serial");

        let mut split = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
            Arc::clone(&program),
            default_koalabear_poseidon2_16(),
        );
        split.witness_stream = witness();
        split.record.index = 7;
        assert!(split.run_split().expect("split"), "split declined");
        assert_eq!(
            split.record.index, serial.record.index,
            "the merge dropped `index`, which `append` does not carry"
        );

        // The mechanisms this test exists to cover, asserted rather than assumed: if a later
        // edit simplifies the program back into something that cannot tell the two paths apart,
        // this fails instead of quietly passing.
        assert!(
            program
                .const_write_positions()
                .iter()
                .any(|i| (*i as usize) >= 2 && (*i as usize) < 13),
            "no constant write inside the children — the hoist would be untested"
        );
        assert_eq!(
            split.record.mem_var_events.len(),
            2,
            "each child should have consumed one hint block"
        );
        assert!(
            !split.record.ext_alu_events.is_empty() && !split.record.base_alu_events.is_empty(),
            "only one event vector populated — the concatenation would be untested"
        );

        assert_eq!(
            serial.record.digest(),
            split.record.digest(),
            "split changed the record"
        );
        assert_eq!(serial.timestamp, split.timestamp);
        assert_eq!(serial.record.mem_const_count, split.record.mem_const_count);
    }

    /// A program the split does not understand runs serially instead of guessing. Both shapes
    /// reach `run_split` in production: convert builds with `n == 1`, and a program restored from
    /// a dump arrives with no ranges at all, since they are `#[serde(skip)]`.
    #[test]
    fn split_declines_shapes_it_does_not_understand() {
        // One case per clause it can reach. `(8,2),(8,13)` is rejected by `e0 == s1` as well as by
        // `s0 <= e0`, so the second case below isolates the latter: `e0 == s1` holds there and
        // only the inversion is left to catch it. The `RECURSION_EARLY_EXIT_TS` clause has no
        // case — it reads a process-wide env var, and setting one from a test would reach every
        // other test sharing the process.
        for spans in [
            vec![],                          // no metadata: a program restored from a dump
            vec![(2, 8)],                    // one child: the convert layer
            vec![(2, 8), (8, 13), (13, 14)], // three children
            vec![(2, 8), (9, 13)],           // a gap, holding code the split would skip
            vec![(8, 2), (8, 13)],           // first range inverted
            vec![(8, 2), (2, 13)],           // inverted while still abutting: isolates s0 <= e0
            vec![(2, 8), (8, 7)],            // second range inverted
            vec![(2, 8), (8, 99)],           // past the end of the program
            vec![(3, 8), (8, 13)],           // a prologue holding more than constant writes
        ] {
            let mut p = tiny_split_program();
            p.child_spans = spans.clone();
            let program = Arc::new(p);
            let mut rt = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
                Arc::clone(&program),
                default_koalabear_poseidon2_16(),
            );
            rt.witness_stream = witness();
            assert!(
                !rt.run_split().expect("declining is not an error"),
                "accepted child_spans it should not understand: {spans:?}"
            );
            // A decline still has to leave a finished run behind. This is the assertion that
            // would have caught the earlier contract, where declining did nothing and a caller
            // who ignored the bool proved an empty record.
            let mut serial = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
                Arc::clone(&program),
                default_koalabear_poseidon2_16(),
            );
            serial.witness_stream = witness();
            serial.run().expect("serial");
            assert_eq!(
                rt.record.digest(),
                serial.record.digest(),
                "declined but did not produce the serial record: {spans:?}"
            );
            assert_eq!(rt.timestamp, serial.timestamp, "declined: {spans:?}");
            assert!(rt.witness_stream.is_empty(), "declined: {spans:?}");
        }
    }

    /// A straight-line program whose level order differs from program order: `C` depends on `A`
    /// and comes before the independent `B` and `D`, so `A` and `D` share a level and so do `C`
    /// and `B`; a second `Hint` sits between them, so the witness stream drains in program order
    /// only if the plan keeps the depth-1 instructions in order.
    fn tiny_planned_program() -> RecursionProgram<Kb> {
        let (add, mul) = (BaseAluOpcode::AddF, BaseAluOpcode::MulF);
        let a = |i: u32| Address(Kb::from_u32(i));
        let hint = |addr: u32| {
            Instruction::Hint(HintInstr {
                output_addrs_mults: vec![(a(addr), Kb::ONE)],
            })
        };
        let p2 = |input: [u32; PERM_BLOCKS], output: [u32; PERM_BLOCKS]| {
            Instruction::Poseidon2Packed(Box::new(Poseidon2PackedInstr {
                input_addrs: input.map(a),
                output_addrs: output.map(a),
                mults: [Kb::ONE; PERM_BLOCKS],
            }))
        };
        let instructions = vec![
            hint(0),
            mem(MemAccessKind::Write, 2, 1, 3),
            mem(MemAccessKind::Write, 2, 2, 5),
            mem(MemAccessKind::Write, 2, 3, 7),
            p2([0, 1, 2, 3], [4, 5, 6, 7]),   // A, depth 2
            p2([4, 5, 1, 2], [8, 9, 10, 11]), // C, depth 3
            hint(12),
            base_alu(add, 1, 13, 12, 3),         // depth 2
            p2([3, 2, 1, 13], [14, 15, 16, 17]), // B, depth 3
            p2([0, 1, 2, 12], [18, 19, 20, 21]), // D, depth 2
            ext_alu(ExtAluOpcode::AddE, 1, 22, 8, 14),
            base_alu(mul, 0, 23, 22, 21),
        ];
        RecursionProgram {
            instructions,
            total_memory: 24,
            ..Default::default()
        }
    }

    fn census_of(program: &Arc<RecursionProgram<Kb>>) -> (u64, Vec<u32>, Vec<(u32, u8, u32)>) {
        let mut rt = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
            Arc::clone(program),
            default_koalabear_poseidon2_16(),
        );
        rt.witness_stream = witness();
        let (depth, entries) = rt.census().expect("census");
        (rt.record.digest(), depth, entries)
    }

    /// Permutes one state at a time, as the prover's batch does for a lone state, and keeps the
    /// widest batch it was handed.
    fn counting_batch_perm(widest: Arc<std::sync::atomic::AtomicUsize>) -> BatchPerm<Kb> {
        let perm = default_koalabear_poseidon2_16();
        Arc::new(move |states: &mut [[Kb; PERMUTATION_WIDTH]]| {
            widest.fetch_max(states.len(), std::sync::atomic::Ordering::Relaxed);
            for s in states.iter_mut() {
                *s = perm.permute(*s);
            }
        })
    }

    /// The gate the planned run rests on: running by plan, with each level's permutations batched,
    /// must produce the record the in-order run produces, the census run included. Windows of one
    /// (program order), of five (a level cut across windows) and the prover's.
    #[test]
    fn planned_and_in_order_produce_the_same_record() {
        let program = Arc::new(tiny_planned_program());
        let mut serial = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
            Arc::clone(&program),
            default_koalabear_poseidon2_16(),
        );
        serial.witness_stream = witness();
        serial.run().expect("serial");
        let want = serial.record.digest();

        let (census, depth, entries) = census_of(&program);
        assert_eq!(census, want, "the census run's record differs");
        assert_eq!(depth, [1, 1, 1, 1, 2, 3, 1, 2, 3, 2, 4, 5]);

        let is_p2 = |i: usize| matches!(program.instructions[i], Instruction::Poseidon2Packed(_));
        for window in [1, 5, WAVEFRONT_WINDOW] {
            let n = program.instructions.len();
            let plan = WavefrontPlan::new(0, n, &depth, &entries, window, is_p2);
            let widest = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let mut planned = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
                Arc::clone(&program),
                default_koalabear_poseidon2_16(),
            );
            planned.witness_stream = witness();
            planned.batch_perm = Some(counting_batch_perm(Arc::clone(&widest)));
            planned.run_range_planned(&plan, false).expect("planned");
            assert_eq!(planned.record.digest(), want, "window {window}");
            assert_eq!(planned.timestamp, serial.timestamp, "window {window}");
            let widest = widest.load(std::sync::atomic::Ordering::Relaxed);
            if window == WAVEFRONT_WINDOW {
                assert_eq!(widest, 2, "A and D, then C and B, should each be one batch");
            }
        }
    }

    /// The same gate for a split node whose children run by plan.
    #[test]
    fn planned_split_and_serial_produce_the_same_record() {
        let program = Arc::new(tiny_split_program());
        let (want, depth, entries) = census_of(&program);
        let is_p2 = |i: usize| matches!(program.instructions[i], Instruction::Poseidon2Packed(_));
        let [(s0, e0), (s1, e1)] = program.child_spans[..] else {
            unreachable!()
        };
        let plans = Arc::new([
            WavefrontPlan::new(s0, e0, &depth, &entries, WAVEFRONT_WINDOW, is_p2),
            WavefrontPlan::new(s1, e1, &depth, &entries, WAVEFRONT_WINDOW, is_p2),
        ]);
        let mut split = Runtime::<Kb, EF, _, _, KOALABEAR_S_BOX_DEGREE>::new(
            Arc::clone(&program),
            default_koalabear_poseidon2_16(),
        );
        split.witness_stream = witness();
        split.child_plans = Some(plans);
        assert!(split.run_split().expect("split"), "split declined");
        assert_eq!(split.record.digest(), want);
    }
}
