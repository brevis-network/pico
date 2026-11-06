//! Event Counter Module
//!
//! This module provides functionality for counting and tracking various types of events
//! in the RISC-V emulator. It includes support for CPU events, ALU operations,
//! memory operations, and precompile events.
//!
//! # Performance Optimizations
//!
//! - Modular counting functions to reduce code duplication
//! - Efficient data structures for memory usage

use crate::{
    chips::chips::{
        riscv_global::GlobalChip,
        riscv_memory::{
            initialize_finalize::MemoryInitializeFinalizeChip,
            local::{traces::local_mem_global_events, MemoryLocalChip},
        },
    },
    emulator::{
        record::RecordBehavior,
        riscv::{
            history::ExecutionHistory,
            history_fill::DerivedRows,
            history_view::history_of,
            record::EmulationRecord,
            syscalls::{precompiles::PrecompileLocalMemory, SyscallCode},
        },
    },
    machine::chip::GpuChipBehavior,
};
use p3_field::PrimeField32;

pub use crate::chips::chips::riscv_cpu::event::CpuExtraEventIndices;

pub use crate::chips::chips::alu::divrem::utils::DivremExtraEventIndices;

/// Start indices for recording extra events on GPU memory
///
/// Provides starting indices for various types of extra events
/// to ensure proper alignment and organization in GPU memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StartIndices {
    pub memory_initialize_extra_global_start_index: usize,
    pub memory_finalize_extra_global_start_index: usize,
    pub memory_local_extra_global_start_index: usize,
    pub syscall_riscv_extra_global_lookup_start_index: usize,
    pub syscall_precompile_extra_global_lookup_start_index: usize,
    pub global_extra_poseidon2_start_index: usize,
}

/// Precompile event counts organized by category
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PrecompileCounts {
    // Hash functions
    sha_compress: usize,
    sha_extend: usize,
    keccak_p: usize,
    poseidon2_p: usize,

    // Edwards curves
    ed_add: usize,
    ed_decompress: usize,

    // Weierstrass curves
    secp256k1_add: usize,
    secp256k1_double: usize,
    secp256k1_decompress: usize,
    secp256r1_add: usize,
    secp256r1_double: usize,
    secp256r1_decompress: usize,
    bn254_add: usize,
    bn254_double: usize,
    bls381_add: usize,
    bls381_double: usize,
    bls381_decompress: usize,

    // Field operations
    fp_bn254: usize,
    fp_bls381: usize,
    fp_secp256k1: usize,
    fp2_add_sub_bn254: usize,
    fp2_mul_bn254: usize,
    fp2_add_sub_bls381: usize,
    fp2_mul_bls381: usize,

    // Other
    u256_mul: usize,
}

/// Precompile local memory event counts organized by category
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct PrecompileLocalMemCounts {
    // Hash functions
    sha_compress: usize,
    sha_extend: usize,
    keccak_p: usize,
    poseidon2_p: usize,

    // Edwards curves
    ed_add: usize,
    ed_decompress: usize,

    // Weierstrass curves
    secp256k1_add: usize,
    secp256k1_double: usize,
    secp256k1_decompress: usize,
    secp256r1_add: usize,
    secp256r1_double: usize,
    secp256r1_decompress: usize,
    bn254_add: usize,
    bn254_double: usize,
    bls381_add: usize,
    bls381_double: usize,
    bls381_decompress: usize,

    // Field operations
    fp_bn254: usize,
    fp_bls381: usize,
    fp_secp256k1: usize,
    fp2_add_sub_bn254: usize,
    fp2_mul_bn254: usize,
    fp2_add_sub_bls381: usize,
    fp2_mul_bls381: usize,

    // Other
    u256_mul: usize,
}

/// Event counter for tracking all types of events in the RISC-V emulator
///
/// This struct maintains counts for various event types including:
/// - CPU events and operations
/// - ALU operations (add, sub, mul, bitwise, shifts, etc.)
/// - Memory operations (initialize, finalize, local access)
/// - Precompile events (hash functions, elliptic curves, field operations, etc.)
/// - System events (syscalls, global lookups)
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EventCounter {
    pub chunk_index: usize,
    pub num_cpu_events: usize,
    pub num_add_sub_events: usize,
    pub num_add_events: usize,
    pub num_sub_events: usize,
    pub num_addw_events: usize,
    pub num_subw_events: usize,
    pub num_mul_events: usize,
    pub num_bitwise_events: usize,
    pub num_shift_left_events: usize,
    pub num_shift_right_events: usize,
    pub num_divrem_events: usize,
    pub num_lt_events: usize,
    pub num_memory_initialize_events: usize,
    pub num_memory_finalize_events: usize,
    pub num_cpu_local_memory_access: usize,

    // Precompile events organized by category
    precompile_counts: PrecompileCounts,
    precompile_local_mem_counts: PrecompileLocalMemCounts,

    // Total precompile local memory events, which the local memory chip proves beside the CPU's
    pub total_precompile_local_mem_events: usize,

    // System events
    pub num_syscall_events: usize,
    pub num_precompile_syscall_events: usize,
    pub num_poseidon2_events: usize,
    pub num_global_lookup_events: usize,
    pub num_memory_read_writes: usize,

    pub start_indices: StartIndices,

    /// The device fill header's counts, from the host's scan of the history a record carries; `None`
    /// for a deferred record, which carries none and uploads none.
    pub history_header: Option<DerivedRows>,
}

impl EventCounter {
    /// Get precompile event count for a specific syscall code
    pub fn get_precompile_event_num(&self, syscall_code: SyscallCode) -> usize {
        match syscall_code {
            SyscallCode::SHA_COMPRESS => self.precompile_counts.sha_compress,
            SyscallCode::SHA_EXTEND => self.precompile_counts.sha_extend,
            SyscallCode::ED_ADD => self.precompile_counts.ed_add,
            SyscallCode::ED_DECOMPRESS => self.precompile_counts.ed_decompress,
            SyscallCode::KECCAK_PERMUTE => self.precompile_counts.keccak_p,
            SyscallCode::POSEIDON2_PERMUTE => self.precompile_counts.poseidon2_p,
            SyscallCode::UINT256_MUL => self.precompile_counts.u256_mul,
            SyscallCode::SECP256K1_ADD => self.precompile_counts.secp256k1_add,
            SyscallCode::SECP256K1_DOUBLE => self.precompile_counts.secp256k1_double,
            SyscallCode::SECP256K1_DECOMPRESS => self.precompile_counts.secp256k1_decompress,
            SyscallCode::SECP256R1_ADD => self.precompile_counts.secp256r1_add,
            SyscallCode::SECP256R1_DOUBLE => self.precompile_counts.secp256r1_double,
            SyscallCode::SECP256R1_DECOMPRESS => self.precompile_counts.secp256r1_decompress,
            SyscallCode::BN254_ADD => self.precompile_counts.bn254_add,
            SyscallCode::BN254_DOUBLE => self.precompile_counts.bn254_double,
            SyscallCode::BLS12381_ADD => self.precompile_counts.bls381_add,
            SyscallCode::BLS12381_DOUBLE => self.precompile_counts.bls381_double,
            SyscallCode::BLS12381_DECOMPRESS => self.precompile_counts.bls381_decompress,
            SyscallCode::BN254_FP_ADD => self.precompile_counts.fp_bn254,
            SyscallCode::BLS12381_FP_ADD => self.precompile_counts.fp_bls381,
            SyscallCode::SECP256K1_FP_ADD => self.precompile_counts.fp_secp256k1,
            SyscallCode::BN254_FP2_ADD => self.precompile_counts.fp2_add_sub_bn254,
            SyscallCode::BN254_FP2_MUL => self.precompile_counts.fp2_mul_bn254,
            SyscallCode::BLS12381_FP2_ADD => self.precompile_counts.fp2_add_sub_bls381,
            SyscallCode::BLS12381_FP2_MUL => self.precompile_counts.fp2_mul_bls381,
            _ => {
                panic!("Unsupported syscall code: {:?}", syscall_code);
            }
        }
    }

    /// Get precompile local memory event count for a specific syscall code
    pub fn get_precomplie_local_mem_event_num(&self, syscall_code: SyscallCode) -> usize {
        match syscall_code {
            SyscallCode::SHA_COMPRESS => self.precompile_local_mem_counts.sha_compress,
            SyscallCode::SHA_EXTEND => self.precompile_local_mem_counts.sha_extend,
            SyscallCode::ED_ADD => self.precompile_local_mem_counts.ed_add,
            SyscallCode::ED_DECOMPRESS => self.precompile_local_mem_counts.ed_decompress,
            SyscallCode::KECCAK_PERMUTE => self.precompile_local_mem_counts.keccak_p,
            SyscallCode::POSEIDON2_PERMUTE => self.precompile_local_mem_counts.poseidon2_p,
            SyscallCode::UINT256_MUL => self.precompile_local_mem_counts.u256_mul,
            SyscallCode::SECP256K1_ADD => self.precompile_local_mem_counts.secp256k1_add,
            SyscallCode::SECP256K1_DOUBLE => self.precompile_local_mem_counts.secp256k1_double,
            SyscallCode::SECP256K1_DECOMPRESS => {
                self.precompile_local_mem_counts.secp256k1_decompress
            }
            SyscallCode::SECP256R1_ADD => self.precompile_local_mem_counts.secp256r1_add,
            SyscallCode::SECP256R1_DOUBLE => self.precompile_local_mem_counts.secp256r1_double,
            SyscallCode::SECP256R1_DECOMPRESS => {
                self.precompile_local_mem_counts.secp256r1_decompress
            }
            SyscallCode::BN254_ADD => self.precompile_local_mem_counts.bn254_add,
            SyscallCode::BN254_DOUBLE => self.precompile_local_mem_counts.bn254_double,
            SyscallCode::BLS12381_ADD => self.precompile_local_mem_counts.bls381_add,
            SyscallCode::BLS12381_DOUBLE => self.precompile_local_mem_counts.bls381_double,
            SyscallCode::BLS12381_DECOMPRESS => self.precompile_local_mem_counts.bls381_decompress,
            SyscallCode::BN254_FP_ADD => self.precompile_local_mem_counts.fp_bn254,
            SyscallCode::BLS12381_FP_ADD => self.precompile_local_mem_counts.fp_bls381,
            SyscallCode::SECP256K1_FP_ADD => self.precompile_local_mem_counts.fp_secp256k1,
            SyscallCode::BN254_FP2_ADD => self.precompile_local_mem_counts.fp2_add_sub_bn254,
            SyscallCode::BN254_FP2_MUL => self.precompile_local_mem_counts.fp2_mul_bn254,
            SyscallCode::BLS12381_FP2_ADD => self.precompile_local_mem_counts.fp2_add_sub_bls381,
            SyscallCode::BLS12381_FP2_MUL => self.precompile_local_mem_counts.fp2_mul_bls381,
            _ => {
                panic!("Unsupported syscall code: {:?}", syscall_code);
            }
        }
    }

    /// Get the total count of all precompile local memory events
    ///
    /// This method sums up all individual precompile local memory event counts
    /// to provide a comprehensive total for all precompile operations.
    pub fn get_total_precompile_local_mem_events(&self) -> usize {
        let counts = &self.precompile_local_mem_counts;
        counts.sha_compress
            + counts.sha_extend
            + counts.ed_add
            + counts.ed_decompress
            + counts.keccak_p
            + counts.poseidon2_p
            + counts.u256_mul
            + counts.secp256k1_add
            + counts.secp256k1_double
            + counts.secp256k1_decompress
            + counts.secp256r1_add
            + counts.secp256r1_double
            + counts.secp256r1_decompress
            + counts.bn254_add
            + counts.bn254_double
            + counts.bls381_add
            + counts.bls381_double
            + counts.bls381_decompress
            + counts.fp_bn254
            + counts.fp_bls381
            + counts.fp_secp256k1
            + counts.fp2_add_sub_bn254
            + counts.fp2_mul_bn254
            + counts.fp2_add_sub_bls381
            + counts.fp2_mul_bls381
    }
}

/// All supported precompile syscall codes
const SUPPORTED_PRECOMPILE_CODES: &[SyscallCode] = &[
    SyscallCode::SHA_COMPRESS,
    SyscallCode::SHA_EXTEND,
    SyscallCode::ED_ADD,
    SyscallCode::ED_DECOMPRESS,
    SyscallCode::KECCAK_PERMUTE,
    SyscallCode::POSEIDON2_PERMUTE,
    SyscallCode::UINT256_MUL,
    SyscallCode::SECP256K1_ADD,
    SyscallCode::SECP256K1_DOUBLE,
    SyscallCode::SECP256K1_DECOMPRESS,
    SyscallCode::SECP256R1_ADD,
    SyscallCode::SECP256R1_DOUBLE,
    SyscallCode::SECP256R1_DECOMPRESS,
    SyscallCode::BN254_ADD,
    SyscallCode::BN254_DOUBLE,
    SyscallCode::BLS12381_ADD,
    SyscallCode::BLS12381_DOUBLE,
    SyscallCode::BLS12381_DECOMPRESS,
    SyscallCode::BN254_FP_ADD,
    SyscallCode::BLS12381_FP_ADD,
    SyscallCode::SECP256K1_FP_ADD,
    SyscallCode::BN254_FP2_ADD,
    SyscallCode::BN254_FP2_MUL,
    SyscallCode::BLS12381_FP2_ADD,
    SyscallCode::BLS12381_FP2_MUL,
];

#[inline]
fn get_precompile_len(record: &EmulationRecord, code: SyscallCode) -> usize {
    record
        .precompile_events
        .get_events(code)
        .map_or(0, |v| v.len())
}

#[inline]
fn get_precompile_local_mem_len(record: &EmulationRecord, code: SyscallCode) -> usize {
    record
        .precompile_events
        .get_events(code)
        .map_or(0, |events| {
            events.get_local_mem_events().into_iter().count()
        })
}

/// Count all precompile events and their local memory events.
fn count_all_precompile_events(
    record: &EmulationRecord,
) -> (PrecompileCounts, PrecompileLocalMemCounts) {
    let mut precompile_counts = PrecompileCounts::default();
    let mut local_mem_counts = PrecompileLocalMemCounts::default();

    for &code in SUPPORTED_PRECOMPILE_CODES {
        let event_count = get_precompile_len(record, code);
        let local_mem_count = get_precompile_local_mem_len(record, code);

        match code {
            SyscallCode::SHA_COMPRESS => {
                precompile_counts.sha_compress = event_count;
                local_mem_counts.sha_compress = local_mem_count;
            }
            SyscallCode::SHA_EXTEND => {
                precompile_counts.sha_extend = event_count;
                local_mem_counts.sha_extend = local_mem_count;
            }
            SyscallCode::ED_ADD => {
                precompile_counts.ed_add = event_count;
                local_mem_counts.ed_add = local_mem_count;
            }
            SyscallCode::ED_DECOMPRESS => {
                precompile_counts.ed_decompress = event_count;
                local_mem_counts.ed_decompress = local_mem_count;
            }
            SyscallCode::KECCAK_PERMUTE => {
                precompile_counts.keccak_p = event_count;
                local_mem_counts.keccak_p = local_mem_count;
            }
            SyscallCode::POSEIDON2_PERMUTE => {
                precompile_counts.poseidon2_p = event_count;
                local_mem_counts.poseidon2_p = local_mem_count;
            }
            SyscallCode::UINT256_MUL => {
                precompile_counts.u256_mul = event_count;
                local_mem_counts.u256_mul = local_mem_count;
            }
            SyscallCode::SECP256K1_ADD => {
                precompile_counts.secp256k1_add = event_count;
                local_mem_counts.secp256k1_add = local_mem_count;
            }
            SyscallCode::SECP256K1_DOUBLE => {
                precompile_counts.secp256k1_double = event_count;
                local_mem_counts.secp256k1_double = local_mem_count;
            }
            SyscallCode::SECP256K1_DECOMPRESS => {
                precompile_counts.secp256k1_decompress = event_count;
                local_mem_counts.secp256k1_decompress = local_mem_count;
            }
            SyscallCode::SECP256R1_ADD => {
                precompile_counts.secp256r1_add = event_count;
                local_mem_counts.secp256r1_add = local_mem_count;
            }
            SyscallCode::SECP256R1_DOUBLE => {
                precompile_counts.secp256r1_double = event_count;
                local_mem_counts.secp256r1_double = local_mem_count;
            }
            SyscallCode::SECP256R1_DECOMPRESS => {
                precompile_counts.secp256r1_decompress = event_count;
                local_mem_counts.secp256r1_decompress = local_mem_count;
            }
            SyscallCode::BN254_ADD => {
                precompile_counts.bn254_add = event_count;
                local_mem_counts.bn254_add = local_mem_count;
            }
            SyscallCode::BN254_DOUBLE => {
                precompile_counts.bn254_double = event_count;
                local_mem_counts.bn254_double = local_mem_count;
            }
            SyscallCode::BLS12381_ADD => {
                precompile_counts.bls381_add = event_count;
                local_mem_counts.bls381_add = local_mem_count;
            }
            SyscallCode::BLS12381_DOUBLE => {
                precompile_counts.bls381_double = event_count;
                local_mem_counts.bls381_double = local_mem_count;
            }
            SyscallCode::BLS12381_DECOMPRESS => {
                precompile_counts.bls381_decompress = event_count;
                local_mem_counts.bls381_decompress = local_mem_count;
            }
            SyscallCode::BN254_FP_ADD => {
                precompile_counts.fp_bn254 = event_count;
                local_mem_counts.fp_bn254 = local_mem_count;
            }
            SyscallCode::BLS12381_FP_ADD => {
                precompile_counts.fp_bls381 = event_count;
                local_mem_counts.fp_bls381 = local_mem_count;
            }
            SyscallCode::SECP256K1_FP_ADD => {
                precompile_counts.fp_secp256k1 = event_count;
                local_mem_counts.fp_secp256k1 = local_mem_count;
            }
            SyscallCode::BN254_FP2_ADD => {
                precompile_counts.fp2_add_sub_bn254 = event_count;
                local_mem_counts.fp2_add_sub_bn254 = local_mem_count;
            }
            SyscallCode::BN254_FP2_MUL => {
                precompile_counts.fp2_mul_bn254 = event_count;
                local_mem_counts.fp2_mul_bn254 = local_mem_count;
            }
            SyscallCode::BLS12381_FP2_ADD => {
                precompile_counts.fp2_add_sub_bls381 = event_count;
                local_mem_counts.fp2_add_sub_bls381 = local_mem_count;
            }
            SyscallCode::BLS12381_FP2_MUL => {
                precompile_counts.fp2_mul_bls381 = event_count;
                local_mem_counts.fp2_mul_bls381 = local_mem_count;
            }
            _ => {
                panic!("Unsupported syscall code: {:?}", code);
            }
        }
    }

    (precompile_counts, local_mem_counts)
}

/// Every count the device's trace generation sizes its buffers and traces by, from the record's
/// execution history: a CPU chunk's history, or none for a deferred record, which counts as an empty
/// one. The start indices are running totals, so the order of the steps below is theirs.
///
/// # Panics
///
/// On a CPU chunk's record that carries no history, the one representation it can be counted from.
pub fn precompute_event_size<F: PrimeField32>(record: &EmulationRecord) -> EventCounter {
    let history = history_of(record);
    let header = DerivedRows::of(history, &record.program);
    let mut counter = EventCounter {
        chunk_index: record.chunk_index(),
        history_header: record.history.is_some().then_some(header),
        ..Default::default()
    };
    Traced { history, header }.count::<F>(record, &mut counter);
    counter
}

/// A record's history and the header scan of it.
struct Traced<'a> {
    history: &'a ExecutionHistory,
    header: DerivedRows,
}

impl Traced<'_> {
    fn count<F: PrimeField32>(&self, record: &EmulationRecord, counter: &mut EventCounter) {
        self.count_alu_rows(counter);
        counter.num_global_lookup_events = record.global_lookup_events.len();
        counter.num_poseidon2_events = record.poseidon2_events.len();

        self.count_cpu_extras(counter);

        counter
            .start_indices
            .memory_initialize_extra_global_start_index = counter.num_memory_initialize_events;
        MemoryInitializeFinalizeChip::<F>::count_extra_records(record, counter);
        counter
            .start_indices
            .memory_finalize_extra_global_start_index = counter
            .start_indices
            .memory_initialize_extra_global_start_index
            + counter.num_memory_initialize_events;

        let (precompile_counts, local_mem_counts) = count_all_precompile_events(record);
        counter.precompile_counts = precompile_counts;
        counter.precompile_local_mem_counts = local_mem_counts;
        counter.total_precompile_local_mem_events = counter.get_total_precompile_local_mem_events();

        // Global events: two per entry less one per fresh entry (`riscv_memory/event.rs`), for the
        // precompile entries here and the CPU entries in `MemoryLocalChip::count_extra_records`;
        // the GPU kernel places each entry's events at the prefix sum
        // `FfiMemoryLocalEvent::global_slot`, so the two counts must agree.
        counter.start_indices.memory_local_extra_global_start_index =
            counter.num_global_lookup_events;
        counter.num_cpu_local_memory_access += counter.total_precompile_local_mem_events;
        counter.num_global_lookup_events += local_mem_global_events(
            record.precompile_events.get_local_mem_events(),
            &record.program.memory_image,
        );
        MemoryLocalChip::<F>::count_extra_records(record, counter);

        self.count_memory_rows(counter);

        self.count_divrem_extras(counter);

        counter
            .start_indices
            .syscall_riscv_extra_global_lookup_start_index = counter.num_global_lookup_events;
        self.count_syscalls(record, counter);
        counter
            .start_indices
            .syscall_precompile_extra_global_lookup_start_index = counter
            .start_indices
            .syscall_riscv_extra_global_lookup_start_index
            + counter.num_syscall_events;

        self.count_bitwise_and_shifts(counter);
        counter.start_indices.global_extra_poseidon2_start_index = counter.num_poseidon2_events;
        GlobalChip::<F>::count_extra_records(record, counter);
    }

    /// The ALU rows the emulator records, before any chip derives more.
    fn count_alu_rows(&self, counter: &mut EventCounter) {
        let lists = &self.history.chip_steps;
        let header = self.header;
        counter.num_lt_events = lists.lt.len();
        counter.num_add_sub_events = lists.add.len() + lists.sub.len();
        counter.num_add_events += header.add as usize;
        counter.num_sub_events += header.sub as usize;
        counter.num_addw_events += header.addw as usize;
        counter.num_subw_events += header.subw as usize;
        counter.num_mul_events = lists.mul.len();
    }

    /// The CPU chip's rows and the less-than row each branch step proves its comparison by.
    fn count_cpu_extras(&self, counter: &mut EventCounter) {
        counter.num_cpu_events += self.history.steps.len();
        counter.num_lt_events += self.history.chip_steps.branch.len();
    }

    fn count_memory_rows(&self, counter: &mut EventCounter) {
        let rows = self.history.chip_steps.memory.len();
        if rows > 0 {
            counter.num_memory_read_writes = rows;
        }
    }

    /// The div/rem chip's rows and the ADD rows it derives, which the add chip proves after its
    /// own.
    fn count_divrem_extras(&self, counter: &mut EventCounter) {
        counter.num_divrem_events += self.history.chip_steps.divrem.len();
        let added = self.header.divrem_add as usize;
        counter.num_add_sub_events += added;
        counter.num_add_events += added;
    }

    fn count_syscalls(&self, record: &EmulationRecord, counter: &mut EventCounter) {
        counter.num_syscall_events += self.history.syscalls.len();
        counter.num_global_lookup_events += counter.num_syscall_events;
        counter.num_precompile_syscall_events += record
            .precompile_events
            .events
            .iter()
            .map(|(_, v)| v.len())
            .sum::<usize>();
        counter.num_global_lookup_events += counter.num_precompile_syscall_events;
    }

    fn count_bitwise_and_shifts(&self, counter: &mut EventCounter) {
        let lists = &self.history.chip_steps;
        counter.num_shift_right_events += lists.shift_right.len();
        counter.num_shift_left_events += lists.shift_left.len();
        counter.num_bitwise_events += lists.bitwise.len();
    }
}

impl EventCounter {
    /// Holds the counts to `record` once every chip has appended its extra records: the history's
    /// lists, the branch comparisons the less-than chip proves beside its own rows, and the ADD rows
    /// div/rem derives, which augmentation appends to the record.
    pub fn assert_event_counts_match(&self, record: &EmulationRecord) {
        let history = history_of(record);
        let lists = &history.chip_steps;
        for (what, counted, held) in [
            ("CPU", self.num_cpu_events, history.steps.len()),
            (
                "add/sub",
                self.num_add_sub_events,
                lists.add.len() + lists.sub.len() + record.add_events.len(),
            ),
            ("mul", self.num_mul_events, lists.mul.len()),
            ("bitwise", self.num_bitwise_events, lists.bitwise.len()),
            (
                "shift left",
                self.num_shift_left_events,
                lists.shift_left.len(),
            ),
            (
                "shift right",
                self.num_shift_right_events,
                lists.shift_right.len(),
            ),
            ("div/rem", self.num_divrem_events, lists.divrem.len()),
            (
                "less-than",
                self.num_lt_events,
                lists.lt.len() + lists.branch.len(),
            ),
            (
                "memory initialize",
                self.num_memory_initialize_events,
                record.memory_initialize_events.len(),
            ),
            (
                "memory finalize",
                self.num_memory_finalize_events,
                record.memory_finalize_events.len(),
            ),
            (
                "local memory",
                self.num_cpu_local_memory_access,
                record.get_local_mem_events().count(),
            ),
            ("syscall", self.num_syscall_events, history.syscalls.len()),
            (
                "global lookup",
                self.num_global_lookup_events,
                record.global_lookup_events.len(),
            ),
            (
                "Poseidon2",
                self.num_poseidon2_events,
                record.poseidon2_events.len(),
            ),
        ] {
            assert_eq!(
                counted, held,
                "{what} events: counted {counted}, the record holds {held}"
            );
        }
    }
}
