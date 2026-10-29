//! Packed FFI event formats for the RISC-V trace-gen H2D path (`MLE_PACKED_EVENTS=1`).
//!
//! The trace-gen critical path is copy-engine-bound (DMA total > kernel total per round), and
//! ~95% of the event bytes are `CpuEvent` (304 B each). This module stages a compact mirror of
//! the three pinned event families on the preparer thread:
//!
//!   - `CpuEventPacked`   80 B (was 304 B): drops the fields no GPU kernel reads
//!     (`memory`, `exit_code`) and the per-record redundancies checked below (record.chunk ==
//!     event.chunk, record.timestamp == clk + {3,2,1,0}), and narrows clk/pc/next_pc/op_b/op_c to
//!     32 bits (verified in range). Where an operand has a read record, the single packed field
//!     carries the *record's* value, which is the one the kernels commit — cpu.cuh overwrites the
//!     access column with it and ecall.cuh prefers it. A few rows read the raw operand as well
//!     (see [`reads_raw_operand`]); there the two must agree, and that is checked.
//!   - `MemRecordPacked`  24 B: dense side stream carrying `memory_record` for exactly the
//!     events in `record.memory_read_write_event_indices`, in that order — the MemoryReadWrite
//!     kernel indexes it directly with its dense row index.
//!   - `AddSubEventPacked` 24 B (was 48 B) / `LtEventPacked` 32 B: only the fields the add_sub /
//!     lt trace kernels read (clk and is_imm are dead there; lt also carries the `is_cmp` flag
//!     of a merged branch comparison, whose `a` packs both comparison bits).
//!
//! It also re-stages the fat `bitwise_events` / `shift_left_events` uploads pinned, bytes
//! unchanged ([`StagedAluEvents`]) — same motivation, no format change.
//!
//! Every dropped redundancy is *checked per event* during packing; any violation (or a
//! capacity/pool shortfall) makes `try_stage` return `None` and the chunk silently falls back
//! to the unpacked (fat) path — the packed path is a pure optimization, never a semantic fork.
//!
//! Cross-repo pairing: the CUDA half (pico-gpu's `src/tracegen/riscv/packed_*.hpp`) mirrors
//! these structs with `static_assert(sizeof)` and every `*_packed` FFI entry validates
//! [`PACKED_EVENT_FORMAT_V1`], so an unpaired deploy fails loudly instead of misreading bytes.

use super::{CpuExtraEventIndices, EventCounter};
use crate::{
    chips::{
        chips::{
            events::{AluEvent, CpuEvent},
            riscv_memory::event::MemoryRecordEnum,
        },
        ffi::FfiOption,
    },
    compiler::riscv::opcode::Opcode,
    emulator::riscv::{
        cpu_event_pool::CPU_EVENT_BUFFER_CAPACITY,
        event_pool::{EventPool, PinnedEventBuffer},
        record::EmulationRecord,
    },
    iter::{PicoIterator, PicoSlice, PicoSliceMut},
};
use cudart::memory::CudaHostAllocFlags;
use p3_maybe_rayon::prelude::IndexedParallelIterator;
use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    OnceLock,
};

/// Format handshake passed through every `*_packed` FFI entry; the CUDA side rejects any other
/// value, so a mismatched pico / pico-gpu pair fails loudly at the first chunk.
/// `..02`: `LtEventPacked` byte 25 became `is_cmp` (merged branch comparison).
pub const PACKED_EVENT_FORMAT_V1: usize = 0x50E1_B302;

/// `MLE_PACKED_EVENTS=1` opts in: pack the cpu/add_sub/lt event families into the compact FFI
/// formats above on the preparer thread. Unset leaves every code path byte-identical to the
/// unpacked one, which is what the non-MLE entry points still run.
pub fn packed_events_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| crate::mle::env_flag("MLE_PACKED_EVENTS"))
}

// ─── Packed struct definitions (must stay field-for-field with packed_events.cuh) ───────────

/// Flag bits in [`CpuEventPacked::flags`].
pub const PK_IMM_B: u16 = 1 << 0;
pub const PK_IMM_C: u16 = 1 << 1;
pub const PK_A_SOME: u16 = 1 << 2;
pub const PK_A_WRITE: u16 = 1 << 3;
pub const PK_B_SOME: u16 = 1 << 4;
pub const PK_C_SOME: u16 = 1 << 5;
pub const PK_M_SOME: u16 = 1 << 6;
pub const PK_M_WRITE: u16 = 1 << 7;

/// 80-byte packed mirror of [`CpuEvent`] (see module docs for what is derived vs dropped).
///
/// `a` holds the *committed* op_a value (`a_record.value()` when a record exists): that is the
/// value every GPU consumer actually commits; the raw event `a` is never load-bearing on the
/// GPU (the add kernel recomputes `b+c`, branch records are reads where the two coincide).
#[derive(Debug, Copy, Clone, Default, PartialEq)]
#[repr(C)]
pub struct CpuEventPacked {
    pub clk: u32,
    pub pc: u32,
    pub next_pc: u32,
    pub opcode: u8,
    pub op_a: u8,
    pub flags: u16,
    pub op_b: i32,
    pub op_c: i32,
    pub a: u64,
    pub b: u64,
    pub c: u64,
    /// Write records: previous value. Read records: == `a` (the kernel derives it).
    pub a_prev_value: u64,
    pub a_prev_chunk: u32,
    pub a_prev_ts: u32,
    pub b_prev_chunk: u32,
    pub b_prev_ts: u32,
    pub c_prev_chunk: u32,
    pub c_prev_ts: u32,
}

/// 24-byte packed `memory_record` side-stream entry (dense, ordered exactly like
/// `record.memory_read_write_event_indices`). Read records: `prev_value == value`.
#[derive(Debug, Copy, Clone, Default, PartialEq)]
#[repr(C)]
pub struct MemRecordPacked {
    pub value: u64,
    pub prev_value: u64,
    pub prev_chunk: u32,
    pub prev_ts: u32,
}

/// 24-byte packed AluEvent for the add_sub family (kernels read only opcode/b/c).
#[derive(Debug, Copy, Clone, Default, PartialEq)]
#[repr(C)]
pub struct AddSubEventPacked {
    pub b: u64,
    pub c: u64,
    pub opcode: u8,
    pub _pad: [u8; 7],
}

/// 32-byte packed AluEvent for the lt family (kernel reads opcode/a/b/c/is_cmp).
#[derive(Debug, Copy, Clone, Default, PartialEq)]
#[repr(C)]
pub struct LtEventPacked {
    pub a: u64,
    pub b: u64,
    pub c: u64,
    pub opcode: u8,
    /// Merged branch comparison flag (`AluEvent::is_cmp`), 0/1.
    pub is_cmp: u8,
    pub _pad: [u8; 6],
}

const _: () = assert!(std::mem::size_of::<CpuEventPacked>() == 80);
const _: () = assert!(std::mem::size_of::<MemRecordPacked>() == 24);
const _: () = assert!(std::mem::size_of::<AddSubEventPacked>() == 24);
const _: () = assert!(std::mem::size_of::<LtEventPacked>() == 32);
const _: () = assert!(std::mem::size_of::<CpuEvent>() == 304);
const _: () = assert!(std::mem::size_of::<AluEvent>() == 48);

// Every field, matching the offsetof asserts in packed_events.cuh. A size check alone cannot see
// two same-width fields swapped, and such a reorder would pass the format-version handshake and
// surface only as a failed proof.
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, clk) == 0);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, pc) == 4);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, next_pc) == 8);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, opcode) == 12);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, op_a) == 13);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, flags) == 14);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, op_b) == 16);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, op_c) == 20);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, a) == 24);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, b) == 32);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, c) == 40);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, a_prev_value) == 48);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, a_prev_chunk) == 56);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, a_prev_ts) == 60);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, b_prev_chunk) == 64);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, b_prev_ts) == 68);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, c_prev_chunk) == 72);
const _: () = assert!(std::mem::offset_of!(CpuEventPacked, c_prev_ts) == 76);
const _: () = assert!(std::mem::offset_of!(MemRecordPacked, value) == 0);
const _: () = assert!(std::mem::offset_of!(MemRecordPacked, prev_value) == 8);
const _: () = assert!(std::mem::offset_of!(MemRecordPacked, prev_chunk) == 16);
const _: () = assert!(std::mem::offset_of!(MemRecordPacked, prev_ts) == 20);
const _: () = assert!(std::mem::offset_of!(AddSubEventPacked, b) == 0);
const _: () = assert!(std::mem::offset_of!(AddSubEventPacked, c) == 8);
const _: () = assert!(std::mem::offset_of!(AddSubEventPacked, opcode) == 16);
const _: () = assert!(std::mem::offset_of!(LtEventPacked, a) == 0);
const _: () = assert!(std::mem::offset_of!(LtEventPacked, b) == 8);
const _: () = assert!(std::mem::offset_of!(LtEventPacked, c) == 16);
const _: () = assert!(std::mem::offset_of!(LtEventPacked, opcode) == 24);
const _: () = assert!(std::mem::offset_of!(LtEventPacked, is_cmp) == 25);
// Fat `AluEvent` flags live in former padding; the CUDA `AluEventU64` mirrors these offsets.
const _: () = assert!(std::mem::offset_of!(AluEvent, is_imm) == 40);
const _: () = assert!(std::mem::offset_of!(AluEvent, is_cmp) == 41);

// ─── Pinned staging pools ────────────────────────────────────────────────────────────────────

static PACKED_CPU_POOL: OnceLock<EventPool<CpuEventPacked>> = OnceLock::new();
static PACKED_MEM_POOL: OnceLock<EventPool<MemRecordPacked>> = OnceLock::new();
static PACKED_ADD_SUB_POOL: OnceLock<EventPool<AddSubEventPacked>> = OnceLock::new();
static PACKED_LT_POOL: OnceLock<EventPool<LtEventPacked>> = OnceLock::new();
static PACKED_CPU_IDX_POOL: OnceLock<EventPool<CpuExtraEventIndices>> = OnceLock::new();
static PACKED_MEM_IDX_POOL: OnceLock<EventPool<usize>> = OnceLock::new();
// Pinned re-staging of the two fat `Vec<AluEvent>` streams that never joined the packed families
// (bitwise, shift_left). A pageable source makes the upload's `cudaMemcpyAsync` block the prove
// thread for the whole DMA at pageable bandwidth; staging the same bytes pinned on the preparer
// thread moves that cost off the critical path. Deliberately independent of `PackedEventStage`:
// these help on every chunk, including the ones `try_stage` rejects.
static STAGED_BITWISE_POOL: OnceLock<EventPool<AluEvent>> = OnceLock::new();
static STAGED_SHIFT_LEFT_POOL: OnceLock<EventPool<AluEvent>> = OnceLock::new();

/// Buffer capacities, sized off the shared CHUNK_SIZE-derived cpu capacity.
///
/// The memory streams get the full `cap` because that is their actual bound — `emit_cpu` pushes
/// exactly one index per memory instruction, so they can never exceed the cpu event count. Sizing
/// them by an observed ratio instead cost a whole chunk's packing on a block that ran 50.15%
/// memory instructions, 0.3% over a `cap / 2` allowance. add_sub and lt keep ratios (measured at
/// ~30% and ~0%); if one is ever exceeded the fallback names it and the need, so the next value
/// comes from a measurement rather than another guess.
fn capacities() -> (usize, usize, usize, usize) {
    let cap = *CPU_EVENT_BUFFER_CAPACITY;
    (cap, cap, cap / 2, cap / 8)
}

/// Initialize the packed staging pools (idempotent). Call next to the other MLE event-pool
/// inits; only meaningful when `MLE_PACKED_EVENTS=1`.
pub fn init_packed_event_pools(pool_size: usize, flags: CudaHostAllocFlags) {
    let (c_cpu, c_mem, c_as, c_lt) = capacities();
    let _ = PACKED_CPU_POOL.set(EventPool::new(pool_size, c_cpu, flags));
    let _ = PACKED_MEM_POOL.set(EventPool::new(pool_size, c_mem, flags));
    let _ = PACKED_ADD_SUB_POOL.set(EventPool::new(pool_size, c_as, flags));
    let _ = PACKED_LT_POOL.set(EventPool::new(pool_size, c_lt, flags));
    // Index side-streams (pageable Vec uploads in the fat path; staged pinned here):
    // cpu extras 16B x n_cpu, memrw event indices 8B x n_mem.
    let _ = PACKED_CPU_IDX_POOL.set(EventPool::new(pool_size, c_cpu, flags));
    let _ = PACKED_MEM_IDX_POOL.set(EventPool::new(pool_size, c_mem, flags));
    let c_alu = fat_alu_capacity();
    let _ = STAGED_BITWISE_POOL.set(EventPool::new(pool_size, c_alu, flags));
    let _ = STAGED_SHIFT_LEFT_POOL.set(EventPool::new(pool_size, c_alu, flags));
    // `bench` for the same reason as the fallback lines below: without it, a run gives no sign of
    // whether packing is on at all, since the module target is filtered out at the operating point.
    // Report the byte total, not just four of the six element counts: the two index pools are
    // another ~200 MB per slot, and the pinned footprint is what an operator has to budget for.
    let per_slot = c_cpu * size_of::<CpuEventPacked>()
        + c_mem * size_of::<MemRecordPacked>()
        + c_as * size_of::<AddSubEventPacked>()
        + c_lt * size_of::<LtEventPacked>()
        + c_cpu * size_of::<CpuExtraEventIndices>()
        + c_mem * size_of::<usize>()
        + 2 * c_alu * size_of::<AluEvent>();
    tracing::info!(
        target: "bench",
        "packed event pools initialized: {pool_size} x (cpu {c_cpu} + mem {c_mem} + add_sub {c_as} \
         + lt {c_lt} + 2 alu {c_alu}) events, {:.2} GiB pinned",
        (pool_size * per_slot) as f64 / (1u64 << 30) as f64
    );
}

pub fn packed_pools_initialized() -> bool {
    // Every pool, not just the first one set: a partially initialized set used to clear this gate
    // and then drop out of `try_stage`'s `?` with no diagnostic, so the run looked like it packed.
    PACKED_CPU_POOL.get().is_some()
        && PACKED_MEM_POOL.get().is_some()
        && PACKED_ADD_SUB_POOL.get().is_some()
        && PACKED_LT_POOL.get().is_some()
        && PACKED_CPU_IDX_POOL.get().is_some()
        && PACKED_MEM_IDX_POOL.get().is_some()
        && STAGED_BITWISE_POOL.get().is_some()
        && STAGED_SHIFT_LEFT_POOL.get().is_some()
}

// ─── Fat ALU stream re-staging (independent of the packed stage) ─────────────────────────────

/// Per-chunk pinned copies of the fat `bitwise_events` / `shift_left_events` uploads. Owned by
/// `PreparedGpuEvents` NEXT TO `packed`, never inside it: `try_stage`'s all-or-nothing fallback
/// (pool empty, packing invariant, gate off) must not take these down with it. Each stream is an
/// independent `Option`; a miss on one leaves the other staged and the upload site falls back to
/// the pageable `Vec` for exactly that stream. Buffers return to their pools on drop.
#[derive(Debug, Default)]
pub struct StagedAluEvents {
    bitwise: Option<PinnedEventBuffer<AluEvent>>,
    shift_left: Option<PinnedEventBuffer<AluEvent>>,
}

impl Drop for StagedAluEvents {
    fn drop(&mut self) {
        if let (Some(b), Some(p)) = (self.bitwise.take(), STAGED_BITWISE_POOL.get()) {
            p.return_buffer(b);
        }
        if let (Some(b), Some(p)) = (self.shift_left.take(), STAGED_SHIFT_LEFT_POOL.get()) {
            p.return_buffer(b);
        }
    }
}

impl StagedAluEvents {
    /// The staged bitwise stream, or `&[]` when this chunk's copy stayed pageable.
    pub fn bitwise(&self) -> &[AluEvent] {
        self.bitwise.as_ref().map_or(&[], |b| b.as_slice())
    }
    /// The staged shift_left stream, or `&[]` when this chunk's copy stayed pageable.
    pub fn shift_left(&self) -> &[AluEvent] {
        self.shift_left.as_ref().map_or(&[], |b| b.as_slice())
    }
}

/// Fat `Vec<AluEvent>` staging capacity (bitwise, shift_left): cap/4 covers the measured
/// per-chunk counts (~0.8M / ~0.5M events) with headroom; overflow falls back per stream.
fn fat_alu_capacity() -> usize {
    *CPU_EVENT_BUFFER_CAPACITY / 4
}

/// Stage the two fat ALU event streams into pinned buffers on the preparer thread. Per-stream
/// best effort: a miss logs its cause and leaves that stream pageable.
pub fn try_stage_alu(record: &EmulationRecord, chunk_index: usize) -> StagedAluEvents {
    if !packed_events_enabled() || !packed_pools_initialized() {
        return StagedAluEvents::default();
    }
    StagedAluEvents {
        bitwise: stage_fat_alu(
            chunk_index,
            "bitwise",
            &record.bitwise_events,
            &STAGED_BITWISE_POOL,
        ),
        shift_left: stage_fat_alu(
            chunk_index,
            "shift_left",
            &record.shift_left_events,
            &STAGED_SHIFT_LEFT_POOL,
        ),
    }
}

fn stage_fat_alu(
    chunk: usize,
    name: &str,
    src: &[AluEvent],
    pool: &OnceLock<EventPool<AluEvent>>,
) -> Option<PinnedEventBuffer<AluEvent>> {
    if src.is_empty() {
        return None;
    }
    let staged = stage_slice(pool.get()?, src);
    if staged.is_none() {
        // Pool depth and stream capacity need opposite fixes — name which one fell short.
        let cap = fat_alu_capacity();
        let why = if src.len() > cap {
            "capacity exceeded"
        } else {
            "pool empty"
        };
        tracing::info!(
            target: "bench",
            "packed-events: chunk {chunk} {name} stream stayed pageable ({why}: need {}, cap {cap})",
            src.len()
        );
    }
    staged
}

// ─── Staged product ──────────────────────────────────────────────────────────────────────────

/// The packed pinned staging of one chunk's cpu/mem/add_sub/lt event families. Owned by
/// `PreparedGpuEvents` (Arc-shared to keep it `Clone`); buffers return to their pools on drop.
#[derive(Debug)]
pub struct PackedEventStage {
    /// The chunk id shared by every event (verified during packing); passed to the packed
    /// kernels as a scalar instead of 8 bytes per event.
    pub chunk: u32,
    cpu: Option<PinnedEventBuffer<CpuEventPacked>>,
    mem: Option<PinnedEventBuffer<MemRecordPacked>>,
    add_sub: Option<PinnedEventBuffer<AddSubEventPacked>>,
    lt: Option<PinnedEventBuffer<LtEventPacked>>,
    cpu_extra_indices: Option<PinnedEventBuffer<CpuExtraEventIndices>>,
    mem_event_indices: Option<PinnedEventBuffer<usize>>,
}

impl Drop for PackedEventStage {
    fn drop(&mut self) {
        if let (Some(b), Some(p)) = (self.cpu.take(), PACKED_CPU_POOL.get()) {
            p.return_buffer(b);
        }
        if let (Some(b), Some(p)) = (self.mem.take(), PACKED_MEM_POOL.get()) {
            p.return_buffer(b);
        }
        if let (Some(b), Some(p)) = (self.add_sub.take(), PACKED_ADD_SUB_POOL.get()) {
            p.return_buffer(b);
        }
        if let (Some(b), Some(p)) = (self.lt.take(), PACKED_LT_POOL.get()) {
            p.return_buffer(b);
        }
        if let (Some(b), Some(p)) = (self.cpu_extra_indices.take(), PACKED_CPU_IDX_POOL.get()) {
            p.return_buffer(b);
        }
        if let (Some(b), Some(p)) = (self.mem_event_indices.take(), PACKED_MEM_IDX_POOL.get()) {
            p.return_buffer(b);
        }
    }
}

impl PackedEventStage {
    pub fn cpu_events(&self) -> &[CpuEventPacked] {
        self.cpu.as_ref().map_or(&[], |b| b.as_slice())
    }
    pub fn mem_records(&self) -> &[MemRecordPacked] {
        self.mem.as_ref().map_or(&[], |b| b.as_slice())
    }
    pub fn add_sub_events(&self) -> &[AddSubEventPacked] {
        self.add_sub.as_ref().map_or(&[], |b| b.as_slice())
    }
    pub fn lt_events(&self) -> &[LtEventPacked] {
        self.lt.as_ref().map_or(&[], |b| b.as_slice())
    }
    pub fn cpu_extra_indices(&self) -> &[CpuExtraEventIndices] {
        self.cpu_extra_indices
            .as_ref()
            .map_or(&[], |b| b.as_slice())
    }
    pub fn mem_event_indices(&self) -> &[usize] {
        self.mem_event_indices
            .as_ref()
            .map_or(&[], |b| b.as_slice())
    }
}

// ─── Per-event packing (all dropped redundancies are *checked* here) ────────────────────────

/// Rows whose kernel path reads an operand's raw event value as well as its access column: branch
/// compares and jump targets in cpu.cuh and the memory address (`b + c`) in
/// memory_read_write.cuh. One packed field cannot hold both values, so these rows require the two
/// to be equal — everywhere else the record's value is the only one that reaches the trace.
///
/// The AUIPC arm never fires: since X12 the transpiler re-encodes `AUIPC rd, imm` as the
/// two-immediate `ADD rd, imm, pc`, so no compiled program carries that opcode at all (and even
/// before that, AUIPC carried no b record on this ISA). It is kept so the rule cannot drift if a
/// future encoding path reintroduces the opcode.
#[inline]
fn reads_raw_operand(e: &CpuEvent) -> bool {
    e.instruction.is_branch_instruction()
        || e.instruction.is_jump_instruction()
        || e.instruction.is_memory_instruction()
        || e.instruction.opcode == Opcode::AUIPC
}

#[inline]
fn fits_i32(v: u64) -> Option<i32> {
    let s = v as i64;
    let t = s as i32;
    (t as i64 == s).then_some(t)
}

/// Which invariant a rejected event broke. Reported with the fallback so the cause is visible:
/// "a chunk fell back" on its own cannot distinguish an exhausted pool from a broken assumption.
pub const RJ_CHUNK: u8 = 1;
pub const RJ_CLK: u8 = 2;
pub const RJ_PC: u8 = 3;
pub const RJ_NEXT_PC: u8 = 4;
pub const RJ_OP_B: u8 = 5;
pub const RJ_OP_C: u8 = 6;
pub const RJ_A_READ: u8 = 7;
pub const RJ_A_WRITE: u8 = 8;
pub const RJ_A_JUMP: u8 = 9;
pub const RJ_B_READ: u8 = 10;
pub const RJ_B_CHUNK: u32 = 20;
pub const RJ_B_TS: u32 = 21;
pub const RJ_B_VALUE: u32 = 22;
pub const RJ_A_CHUNK: u32 = 30;
pub const RJ_A_TS: u32 = 31;
pub const RJ_A_VALUE: u32 = 32;
pub const RJ_C_CHUNK: u32 = 40;
pub const RJ_C_TS: u32 = 41;
pub const RJ_C_VALUE: u32 = 42;
pub const RJ_B_IS_WRITE: u8 = 11;
pub const RJ_C_READ: u8 = 12;
pub const RJ_C_IS_WRITE: u8 = 13;
pub const RJ_MEM: u8 = 14;
/// Not a rejection: the staging pool had no free buffer, so nothing was inspected.
pub const RJ_POOL: u32 = 100;
/// Not a rejection either: a memory_read_write index pointed past the cpu event array.
pub const RJ_MEM_INDEX: u32 = 101;

/// Per-chunk tally of why events were rejected. `MLE_PACKED_CENSUS=1` keeps scanning after the
/// first rejection so one run reports the whole distribution instead of whichever event lost the
/// race; without it the scan still stops early and the tally holds just that event.
pub struct Census {
    /// Indexed by reason code. Sized past the highest code in use, not by a round number: the
    /// pool-exhaustion code sat above a 64-entry bound and its tally was silently dropped, which
    /// is exactly the blindness this type exists to remove.
    counts: [AtomicU64; 128],
    opcode: [AtomicU32; 128],
    /// One example of a mismatching pair (expected, found, pc), for the reasons that compare two
    /// values. Knowing *what* diverged is what tells you whether to carry the value or fix its
    /// producer.
    sample_taken: AtomicBool,
    sample_expected: AtomicU64,
    sample_found: AtomicU64,
    sample_pc: AtomicU64,
}

impl Default for Census {
    fn default() -> Self {
        Self {
            counts: std::array::from_fn(|_| AtomicU64::new(0)),
            opcode: std::array::from_fn(|_| AtomicU32::new(u32::MAX)),
            sample_taken: AtomicBool::new(false),
            sample_expected: AtomicU64::new(0),
            sample_found: AtomicU64::new(0),
            sample_pc: AtomicU64::new(0),
        }
    }
}

impl Census {
    fn sample(&self, expected: u64, found: u64, pc: u64) {
        if self
            .sample_taken
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.sample_expected.store(expected, Ordering::Relaxed);
            self.sample_found.store(found, Ordering::Relaxed);
            self.sample_pc.store(pc, Ordering::Relaxed);
        }
    }

    fn note(&self, packed_code: u32) {
        let idx = (packed_code & 0xFF) as usize;
        if idx >= self.counts.len() {
            return;
        }
        self.counts[idx].fetch_add(1, Ordering::Relaxed);
        let _ = self.opcode[idx].compare_exchange(
            u32::MAX,
            (packed_code >> 8) & 0xFF,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }

    /// "reason xN (opcode K)" for every reason seen, most frequent first.
    pub fn report(&self) -> String {
        let mut rows: Vec<(u64, usize)> = (0..self.counts.len())
            .map(|i| (self.counts[i].load(Ordering::Relaxed), i))
            .filter(|(n, _)| *n > 0)
            .collect();
        rows.sort_unstable_by_key(|&(n, _)| std::cmp::Reverse(n));
        if rows.is_empty() {
            return "no rejections recorded".to_string();
        }
        let body = rows
            .iter()
            .map(|(n, i)| {
                let op = self.opcode[*i].load(Ordering::Relaxed);
                format!("{} x{n} (opcode {op})", rejection_name(*i as u32))
            })
            .collect::<Vec<_>>()
            .join("; ");
        if self.sample_taken.load(Ordering::Relaxed) {
            format!(
                "{body} | example: event={:#x} record={:#x} pc={:#x}",
                self.sample_expected.load(Ordering::Relaxed),
                self.sample_found.load(Ordering::Relaxed),
                self.sample_pc.load(Ordering::Relaxed)
            )
        } else {
            body
        }
    }
}

/// `MLE_PACKED_CENSUS=1`: scan every event even after one is rejected, so the tally is complete.
pub fn packed_census_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| crate::mle::env_flag("MLE_PACKED_CENSUS"))
}

pub fn rejection_name(code: u32) -> &'static str {
    match code {
        c if c == RJ_CHUNK as u32 => "event.chunk != chunk",
        c if c == RJ_CLK as u32 => "clk not u32",
        c if c == RJ_PC as u32 => "pc not u32",
        c if c == RJ_NEXT_PC as u32 => "next_pc not u32",
        c if c == RJ_OP_B as u32 => "op_b not i32",
        c if c == RJ_OP_C as u32 => "op_c not i32",
        c if c == RJ_A_READ as u32 => "a read record (chunk/timestamp/value)",
        c if c == RJ_A_WRITE as u32 => "a write record (chunk/timestamp)",
        c if c == RJ_A_JUMP as u32 => "jump row: a write value != event.a",
        c if c == RJ_B_READ as u32 => "b read record (chunk/timestamp/value)",
        RJ_B_CHUNK => "b read: record.chunk != event.chunk",
        RJ_B_TS => "b read: timestamp != clk + 2",
        RJ_B_VALUE => "b read: record.value != event.b on a row that reads the raw operand",
        RJ_A_CHUNK => "a read: record.chunk != event.chunk",
        RJ_A_TS => "a read: timestamp != clk + 3",
        RJ_A_VALUE => "a read: record.value != event.a",
        RJ_C_CHUNK => "c read: record.chunk != event.chunk",
        RJ_C_TS => "c read: timestamp != clk + 1",
        RJ_C_VALUE => "c read: record.value != event.c",
        c if c == RJ_B_IS_WRITE as u32 => "b record is a write",
        c if c == RJ_C_READ as u32 => "c read record (chunk/timestamp/value)",
        c if c == RJ_C_IS_WRITE as u32 => "c record is a write",
        c if c == RJ_MEM as u32 => "memory record (chunk/timestamp)",
        RJ_POOL => "staging pool empty (not a rejection)",
        RJ_MEM_INDEX => "memory_read_write index >= cpu event count",
        _ => "unknown",
    }
}

/// Pack one `CpuEvent`; `Err(code)` on any violated invariant (the chunk then falls back to the fat
/// path). The invariants are exactly the ones measured to hold on a full production chunk:
/// per-record chunk == event chunk, timestamp == clk + {3(a),2(b),1(c),0(mem)}, read-record
/// value == operand value, clk/pc/next_pc/op_b/op_c in 32-bit range, b/c records read-only.
#[inline]
fn pack_cpu_event(e: &CpuEvent, chunk: u32) -> Result<CpuEventPacked, u32> {
    if e.chunk != chunk {
        return Err(RJ_CHUNK as u32);
    }
    // A clk within 3 of u32::MAX cannot reach the kernels' `clk + pos` arithmetic: with a record
    // the timestamp equality below already fails, and without one no timestamp is recomputed.
    let clk = u32::try_from(e.clk).map_err(|_| RJ_CLK as u32)?;
    let pc = u32::try_from(e.pc).map_err(|_| RJ_PC as u32)?;
    let next_pc = u32::try_from(e.next_pc).map_err(|_| RJ_NEXT_PC as u32)?;
    let op_b = fits_i32(e.instruction.op_b).ok_or(RJ_OP_B as u32)?;
    // `op_c` is an absolute guest address on every row the transpiler re-encoded from AUIPC
    // (`ADD rd, imm, pc`, see `disassembler/rrs.rs`). It fits only because the guest address
    // ceiling is `EMULATOR_MEMORY_SIZE_BYTES = 0x7800_0000` (`disassembler/elf.rs`), which is
    // below `2^31`. Raising that ceiling past `2^31` would make every such row fail `fits_i32`
    // and fall back to the fat path -- a performance cliff, not a correctness bug, and one that
    // would show up as a jump in the `RJ_OP_C` rejection counter rather than as a test failure.
    let op_c = fits_i32(e.instruction.op_c).ok_or(RJ_OP_C as u32)?;

    let mut flags: u16 = 0;
    if e.instruction.imm_b {
        flags |= PK_IMM_B;
    }
    if e.instruction.imm_c {
        flags |= PK_IMM_C;
    }

    let (a, a_prev_value, a_prev_chunk, a_prev_ts) = match &e.a_record {
        FfiOption::Some(MemoryRecordEnum::Read(r)) => {
            if r.chunk != chunk {
                return Err(RJ_A_CHUNK | ((e.instruction.opcode as u8 as u32) << 8));
            }
            if u64::from(r.timestamp) != e.clk + 3 {
                return Err(RJ_A_TS | ((e.instruction.opcode as u8 as u32) << 8));
            }
            if r.value != e.a {
                return Err(RJ_A_VALUE | ((e.instruction.opcode as u8 as u32) << 8));
            }
            flags |= PK_A_SOME;
            (r.value, r.value, r.prev_chunk, r.prev_timestamp)
        }
        FfiOption::Some(MemoryRecordEnum::Write(w)) => {
            if w.chunk != chunk || u64::from(w.timestamp) != e.clk + 3 {
                return Err(RJ_A_WRITE as u32);
            }
            // A jump row is the one place a kernel reads this field as the *event's* `a` rather
            // than the committed one: it proves `pc + 4 == a`. Same guard the kernel gates that
            // branch on, so substituting the record value stays invisible.
            if e.instruction.is_jump_instruction() && e.instruction.op_a != 0 && w.value != e.a {
                return Err(RJ_A_JUMP as u32);
            }
            flags |= PK_A_SOME | PK_A_WRITE;
            (w.value, w.prev_value, w.prev_chunk, w.prev_timestamp)
        }
        FfiOption::None => (e.a, 0, 0, 0),
    };

    let (b_value, b_prev_chunk, b_prev_ts) = match &e.b_record {
        FfiOption::Some(MemoryRecordEnum::Read(r)) => {
            if r.chunk != chunk {
                return Err(RJ_B_CHUNK | ((e.instruction.opcode as u8 as u32) << 8));
            }
            if u64::from(r.timestamp) != e.clk + 2 {
                return Err(RJ_B_TS | ((e.instruction.opcode as u8 as u32) << 8));
            }
            // The packed field feeds both the access column and the kernels' `event.b`, and where
            // a read record exists the record's value is the authoritative one: cpu.cuh overwrites
            // the access column with it, and ecall.cuh prefers it outright. Carry that value; rows
            // that also read the raw operand need the two to agree, since one field cannot hold
            // both.
            if reads_raw_operand(e) && r.value != e.b {
                return Err(RJ_B_VALUE | ((e.instruction.opcode as u8 as u32) << 8));
            }
            flags |= PK_B_SOME;
            (r.value, r.prev_chunk, r.prev_timestamp)
        }
        FfiOption::Some(MemoryRecordEnum::Write(_)) => return Err(RJ_B_IS_WRITE as u32),
        FfiOption::None => (e.b, 0, 0),
    };

    let (c_value, c_prev_chunk, c_prev_ts) = match &e.c_record {
        FfiOption::Some(MemoryRecordEnum::Read(r)) => {
            if r.chunk != chunk {
                return Err(RJ_C_CHUNK | ((e.instruction.opcode as u8 as u32) << 8));
            }
            if u64::from(r.timestamp) != e.clk + 1 {
                return Err(RJ_C_TS | ((e.instruction.opcode as u8 as u32) << 8));
            }
            // Same rule as the b operand above. On today's ISA no such row carries a c record (c is
            // an immediate on every branch, jump and memory instruction), so this never fires; it
            // is here so the two operands cannot drift apart if that changes.
            if reads_raw_operand(e) && r.value != e.c {
                return Err(RJ_C_VALUE | ((e.instruction.opcode as u8 as u32) << 8));
            }
            flags |= PK_C_SOME;
            (r.value, r.prev_chunk, r.prev_timestamp)
        }
        FfiOption::Some(MemoryRecordEnum::Write(_)) => return Err(RJ_C_IS_WRITE as u32),
        FfiOption::None => (e.c, 0, 0),
    };

    match &e.memory_record {
        FfiOption::Some(MemoryRecordEnum::Read(r)) => {
            if r.chunk != chunk || u64::from(r.timestamp) != e.clk {
                return Err(RJ_MEM as u32);
            }
            flags |= PK_M_SOME;
        }
        FfiOption::Some(MemoryRecordEnum::Write(w)) => {
            if w.chunk != chunk || u64::from(w.timestamp) != e.clk {
                return Err(RJ_MEM as u32);
            }
            flags |= PK_M_SOME | PK_M_WRITE;
        }
        FfiOption::None => {}
    }

    Ok(CpuEventPacked {
        clk,
        pc,
        next_pc,
        opcode: e.instruction.opcode as u8,
        op_a: e.instruction.op_a,
        flags,
        op_b,
        op_c,
        a,
        b: b_value,
        c: c_value,
        a_prev_value,
        a_prev_chunk,
        a_prev_ts,
        b_prev_chunk,
        b_prev_ts,
        c_prev_chunk,
        c_prev_ts,
    })
}

/// Extract the packed `memory_record` for an event already validated by [`pack_cpu_event`].
#[inline]
fn pack_mem_record(e: &CpuEvent) -> MemRecordPacked {
    match &e.memory_record {
        FfiOption::Some(MemoryRecordEnum::Read(r)) => MemRecordPacked {
            value: r.value,
            prev_value: r.value,
            prev_chunk: r.prev_chunk,
            prev_ts: r.prev_timestamp,
        },
        FfiOption::Some(MemoryRecordEnum::Write(w)) => MemRecordPacked {
            value: w.value,
            prev_value: w.prev_value,
            prev_chunk: w.prev_chunk,
            prev_ts: w.prev_timestamp,
        },
        FfiOption::None => MemRecordPacked::default(),
    }
}

#[inline]
fn pack_add_sub(e: &AluEvent) -> AddSubEventPacked {
    AddSubEventPacked {
        b: e.b,
        c: e.c,
        opcode: e.opcode as u8,
        _pad: [0; 7],
    }
}

#[inline]
fn pack_lt(e: &AluEvent) -> LtEventPacked {
    LtEventPacked {
        a: e.a,
        b: e.b,
        c: e.c,
        opcode: e.opcode as u8,
        is_cmp: e.is_cmp as u8,
        _pad: [0; 6],
    }
}

// ─── Stage builder ───────────────────────────────────────────────────────────────────────────

/// Acquire a pool buffer (non-blocking) and fill its first `src_len` slots via `fill`, which
/// runs the parallel packing loop and flags failure through the shared `AtomicBool`. Any
/// shortfall (pool empty, capacity, invariant violation) returns `None` = fat fallback.
fn pack_into<T: Copy + Send + std::fmt::Debug>(
    pool: &EventPool<T>,
    src_len: usize,
    fill: impl FnOnce(&mut [std::mem::MaybeUninit<T>], &AtomicBool, &Census),
    census: &Census,
) -> Option<PinnedEventBuffer<T>> {
    let Some(mut buf) = pool.try_get() else {
        census.note(RJ_POOL);
        return None;
    };
    if buf.capacity() < src_len {
        // Distinguishable from a rejection: nothing was inspected.
        census.note(RJ_POOL);
        pool.return_buffer(buf);
        return None;
    }
    let failed = AtomicBool::new(false);
    fill(&mut buf.spare_full_mut()[..src_len], &failed, census);
    if failed.load(Ordering::Relaxed) {
        pool.return_buffer(buf);
        return None;
    }
    // SAFETY: `fill` initialized every element in [0, src_len) (or set `failed`).
    unsafe { buf.set_len(src_len) };
    Some(buf)
}

/// Stage a plain slice into a pool buffer (straight memcpy; used for the index side-streams).
fn stage_slice<T: Copy + Send + std::fmt::Debug>(
    pool: &EventPool<T>,
    src: &[T],
) -> Option<PinnedEventBuffer<T>> {
    let mut buf = pool.try_get()?;
    if buf.capacity() < src.len() {
        pool.return_buffer(buf);
        return None;
    }
    if buf.extend_from_slice(src).is_err() {
        pool.return_buffer(buf);
        return None;
    }
    Some(buf)
}

/// Try to stage the packed event families for `record`. Returns `None` (fat fallback) when the
/// gate is off, pools are missing/exhausted, a capacity is exceeded, or any packing invariant
/// fails. All-or-nothing per chunk: every consumer keys off `PreparedGpuEvents::packed`.
pub fn try_stage(record: &EmulationRecord, counter: &EventCounter) -> Option<PackedEventStage> {
    if !packed_events_enabled() {
        return None;
    }
    stage(record, counter)
}

/// [`try_stage`] without the `MLE_PACKED_EVENTS` gate, for the chip parity tests: a `cargo test`
/// process has the flag unset, so the packed kernels -- the ones production runs -- would never be
/// exercised against the CPU generators. Pools must still be initialized and every packing
/// invariant still applies.
#[cfg(test)]
pub fn try_stage_forced(
    record: &EmulationRecord,
    counter: &EventCounter,
) -> Option<PackedEventStage> {
    stage(record, counter)
}

fn stage(record: &EmulationRecord, counter: &EventCounter) -> Option<PackedEventStage> {
    let cpu_src = record.cpu_events.as_slice();
    let n = cpu_src.len();
    if n == 0 {
        return None;
    }
    if !packed_pools_initialized() {
        static WARNED: OnceLock<()> = OnceLock::new();
        WARNED.get_or_init(|| {
            tracing::warn!("MLE_PACKED_EVENTS=1 but packed pools not initialized; using fat path")
        });
        return None;
    }
    let chunk = cpu_src[0].chunk;
    let chunk_sz = std::cmp::max(n / num_cpus::get(), 4096);

    // Fetch all pools up front: a later early-return must never strand an already-acquired
    // buffer (PinnedEventBuffer's Drop frees pinned memory instead of returning it).
    let (cpu_pool, mem_pool, add_sub_pool, lt_pool) = (
        PACKED_CPU_POOL.get()?,
        PACKED_MEM_POOL.get()?,
        PACKED_ADD_SUB_POOL.get()?,
        PACKED_LT_POOL.get()?,
    );
    let (cpu_idx_pool, mem_idx_pool) = (PACKED_CPU_IDX_POOL.get()?, PACKED_MEM_IDX_POOL.get()?);

    // cpu main stream
    let census_all = packed_census_enabled();
    let cpu_census = Census::default();
    let cpu_buf = pack_into(
        cpu_pool,
        n,
        |dst, failed, census| {
            dst.pico_chunks_mut(chunk_sz)
                .zip_eq(cpu_src.pico_chunks(chunk_sz))
                .for_each(|(dchunk, schunk)| {
                    if failed.load(Ordering::Relaxed) && !census_all {
                        return;
                    }
                    for (d, s) in dchunk.iter_mut().zip(schunk.iter()) {
                        match pack_cpu_event(s, chunk) {
                            Ok(p) => {
                                d.write(p);
                            }
                            Err(code) => {
                                census.note(code);
                                if code & 0xFF == RJ_B_VALUE {
                                    if let FfiOption::Some(MemoryRecordEnum::Read(r)) = &s.b_record
                                    {
                                        census.sample(s.b, r.value, s.pc);
                                    }
                                }
                                failed.store(true, Ordering::Relaxed);
                                if !census_all {
                                    return;
                                }
                            }
                        }
                    }
                });
        },
        &cpu_census,
    );
    let Some(cpu_buf) = cpu_buf else {
        // `bench`, not the module target: a fallback means the run is not getting the traffic
        // saving it was configured for, and the module target is filtered out at the operating
        // point this ships at.
        tracing::info!(
            target: "bench",
            "packed-events: chunk {chunk} fell back to fat path: {}",
            cpu_census.report()
        );
        return None;
    };

    // memory_record side stream, dense in memory_read_write_event_indices order
    let mem_idx = record.memory_read_write_event_indices.as_slice();
    let m = mem_idx.len();
    let mem_census = Census::default();
    let mem_buf = pack_into(
        mem_pool,
        m,
        |dst, failed, census| {
            dst.pico_chunks_mut(chunk_sz)
                .zip_eq(mem_idx.pico_chunks(chunk_sz))
                .for_each(|(dchunk, schunk)| {
                    if failed.load(Ordering::Relaxed) {
                        return;
                    }
                    for (d, &i) in dchunk.iter_mut().zip(schunk.iter()) {
                        if i >= n {
                            census.note(RJ_MEM_INDEX);
                            failed.store(true, Ordering::Relaxed);
                            return;
                        }
                        d.write(pack_mem_record(&cpu_src[i]));
                    }
                });
        },
        &mem_census,
    );

    // add_sub / lt host streams
    let as_src = record.add_sub_events.as_slice();
    let as_census = Census::default();
    let add_sub_buf = pack_into(
        add_sub_pool,
        as_src.len(),
        |dst, _failed, _census| {
            dst.pico_chunks_mut(chunk_sz)
                .zip_eq(as_src.pico_chunks(chunk_sz))
                .for_each(|(dchunk, schunk)| {
                    for (d, s) in dchunk.iter_mut().zip(schunk.iter()) {
                        d.write(pack_add_sub(s));
                    }
                });
        },
        &as_census,
    );
    let lt_src = record.lt_events.as_slice();
    let lt_census = Census::default();
    let lt_buf = pack_into(
        lt_pool,
        lt_src.len(),
        |dst, _failed, _census| {
            dst.pico_chunks_mut(chunk_sz)
                .zip_eq(lt_src.pico_chunks(chunk_sz))
                .for_each(|(dchunk, schunk)| {
                    for (d, s) in dchunk.iter_mut().zip(schunk.iter()) {
                        d.write(pack_lt(s));
                    }
                });
        },
        &lt_census,
    );

    // Index side-streams (straight pinned memcpys of the fat path's pageable Vec uploads).
    let cpu_extra_src = counter.cpu_extra_event_indices.as_slice();
    let cpu_idx_buf = (cpu_extra_src.len() == n)
        .then(|| stage_slice(cpu_idx_pool, cpu_extra_src))
        .flatten();
    let mem_idx_buf = stage_slice(mem_idx_pool, mem_idx);

    match (mem_buf, add_sub_buf, lt_buf, cpu_idx_buf, mem_idx_buf) {
        (Some(mem), Some(add_sub), Some(lt), Some(cpu_idx), Some(mem_ei)) => {
            Some(PackedEventStage {
                chunk,
                cpu: Some(cpu_buf),
                mem: Some(mem),
                add_sub: Some(add_sub),
                lt: Some(lt),
                cpu_extra_indices: Some(cpu_idx),
                mem_event_indices: Some(mem_ei),
            })
        }
        (mem, add_sub, lt, cpu_idx, mem_ei) => {
            // Name the stream and print what it asked for against what the pool holds: a stream
            // that outgrew its capacity ratio and a stream that merely lost the race for a buffer
            // need opposite fixes, and the old message could not tell them apart.
            let (_, c_mem, c_as, c_lt) = capacities();
            let mut why: Vec<String> = Vec::new();
            if mem.is_none() {
                why.push(format!(
                    "mem(need {m}, cap {c_mem}): {}",
                    mem_census.report()
                ));
            }
            if add_sub.is_none() {
                why.push(format!(
                    "add_sub(need {}, cap {c_as}): {}",
                    as_src.len(),
                    as_census.report()
                ));
            }
            if lt.is_none() {
                why.push(format!(
                    "lt(need {}, cap {c_lt}): {}",
                    lt_src.len(),
                    lt_census.report()
                ));
            }
            if cpu_idx.is_none() {
                why.push(format!(
                    "cpu_extra_idx(need {}, must equal n={n})",
                    cpu_extra_src.len()
                ));
            }
            if mem_ei.is_none() {
                why.push(format!("mem_idx(need {m})"));
            }
            // Drop returns whatever was acquired to its pool, then fall back.
            drop(PackedEventStage {
                chunk,
                cpu: Some(cpu_buf),
                mem,
                add_sub,
                lt,
                cpu_extra_indices: cpu_idx,
                mem_event_indices: mem_ei,
            });
            tracing::info!(
                target: "bench",
                "packed-events: chunk {chunk} fell back to fat path (side stream): {}",
                why.join(", ")
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The merged branch-comparison flag rides in what used to be a padding byte; the CUDA
    /// `LtEventPacked` reads it at offset 25 (`packed_events.cuh`).
    #[test]
    fn lt_packed_carries_is_cmp_at_byte_25() {
        let mut e = AluEvent::new(7, Opcode::SLTU, 1, 3, 9, false);
        e.is_cmp = true;
        let p = pack_lt(&e);
        assert_eq!(
            (p.a, p.b, p.c, p.opcode, p.is_cmp),
            (e.a, e.b, e.c, Opcode::SLTU as u8, 1)
        );
        let bytes: [u8; 32] = unsafe { std::mem::transmute(p) };
        assert_eq!(bytes[24], Opcode::SLTU as u8);
        assert_eq!(bytes[25], 1);
        assert!(bytes[26..].iter().all(|&b| b == 0));
        e.is_cmp = false;
        assert_eq!(pack_lt(&e).is_cmp, 0);
    }
}
