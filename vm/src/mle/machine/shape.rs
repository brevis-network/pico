//! Coarse-bucket shape normalization for the MLE RISC-V machine.
//!
//! A bucketed chunk pads every chip in its shape to a fixed per-chip height, and takes its chip
//! SET from the canonical presence set for the chunk kind rather than from the events it happens
//! to raise (`MLE_CORE_CANONICAL_PRESENCE`). A chunk's proof shape therefore depends only on its
//! kind, so same-kind chunks of DIFFERENT guest programs yield identical proof shapes — and, with
//! the program table bucketed, identical RISC-V vk lean pre-hashes, hence identical convert-circuit
//! VKs. That is the prerequisite for a finite recursion-VK whitelist.
//!
//! The heights below are the CATCH-ALL: the shape every chunk of its family fits into, whatever
//! the workload. They are sized against the structural ceilings rather than against measured
//! maxima —
//!
//!   - no height exceeds `log_stacked_height` (23): a taller trace does not pack;
//!   - `Global` is the same in every shape of every family, [`MLE_GLOBAL_LOG_HEIGHT`]: the
//!     Global AIR proves at one fixed height whatever the chunk's event count;
//!   - `MemoryInitialize` and `MemoryFinalize` are each at most 2^22 in a deferred memory chunk
//!     because the emulator buckets each stream in `DEFERRED_MEMORY_BUCKET = 2^20 - 1` events
//!     (`record.rs`) and closes every memory record under the 2^22 event cap: at most four
//!     finalize buckets (2^22 - 4 events) per record, the initialize buckets riding on the last
//!     one under the same cap. Global, one row per memory event, holds them;
//!   - the precompile heights are `max(full-block threshold, tail-merge cap)` per kind, and their
//!     companions follow `get_precompile_shapes`' derivations.
//!
//! A chunk whose event count exceeds its bucket fails loudly at trace-padding time
//! (`pad_to_power_of_two` and the per-chip overrides panic rather than truncate).

use std::{collections::BTreeMap, sync::Arc};

use p3_field::PrimeCharacteristicRing;

use crate::{
    compiler::riscv::program::Program, emulator::riscv::record::EmulationRecord,
    instances::compiler::shapes::riscv_shape::RiscvPadShape, mle::machine::riscv::Kb,
};

/// Catch-all log2 heights per chip (main traces). See the module doc for what sizes them.
///
/// `MemoryLocal` is the one entry whose height depends on the chunk kind, so it is not here:
/// [`bucket_log_height`] takes it from [`MEMORY_LOCAL_CPU_LOG_HEIGHT`] or
/// [`MEMORY_LOCAL_DEFERRED_LOG_HEIGHT`].
pub const MLE_RISCV_MAIN_LOG_HEIGHTS: &[(&str, usize)] = &[
    // ── core family ──
    ("Cpu", 23), // one row per instruction, so this is the stacked cap itself
    ("Add", 22),
    ("Sub", 22),
    ("Mul", 22),
    ("Bitwise", 22),
    ("LessThan", 22),
    ("ShiftLeft", 22),
    ("ShiftRight", 22),
    ("DivRem", 22),
    ("Addw", 22),
    ("Subw", 22),
    // One row per memory access, and a single instruction can touch memory more than once,
    // so this sits at the stacked cap beside Cpu rather than a notch under it. reth reaches
    // 2^23 in 2 of the 658 chunks of the 13-block reth corpus.
    ("MemoryReadWrite", 23),
    // One row per misaligned load or store. The chunk split caps a CPU chunk at this many; a
    // ladder row takes the smallest of `MLE_MEMORY_UNALIGNED_LOG_HEIGHTS` that holds its chunk's.
    ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
    ("SyscallRiscv", 22),
    ("Ecall", 22),
    // Global carries every chunk kind, at one height in all three families.
    ("Global", MLE_GLOBAL_LOG_HEIGHT),
    ("Byte", 17), // fixed-height table; the entry documents (and must equal) its natural 2^17
    // The program table's main multiplicity trace must match its preprocessed height, so it
    // takes the constant rather than a literal.
    ("Program", MLE_RISCV_PROGRAM_LOG_HEIGHT),
    // ── memory family: 2^22 a side. The finalize stream is bucketed on its own
    // (`EmulationRecord::split`) and every memory record closes under the 2^22 event cap, so
    // neither trace exceeds 2^22 - 4 rows. ──
    ("MemoryInitialize", 22),
    ("MemoryFinalize", 22),
    // ── precompile family: max(full-block threshold, tail-merge cap) per kind ──
    // The sliced layout: a full block is 2 * floor(2^19 / 27) = 38836 permutations in 2^19 rows
    // (`EmulationRecord::split`), and a tail remainder is smaller.
    ("KeccakPermute", 19),
    ("ShaExtend", 20),
    ("ShaCompress", 20),
    // Control siblings and the precompile syscall receiver follow
    // `get_precompile_shapes`: ceil(2^h / rows_per_event), rounded up to a power of two.
    ("KeccakControl", 16),
    ("ShaExtendControl", 15),
    ("ShaCompressControl", 14),
    ("SyscallPrecompile", 17), // the 1-row/event kinds at 2^17 dominate here
    // The sliced Keccak lookup tables, fixed at their full height in every Keccak chunk
    // (`precompile_tables`).
    ("KeccakTables", 20),
    // 1 row per event, capped by TAIL_MERGE_MAX_WIDE_ROWS = 2^17.
    ("Uint256MulMod", 17),
    ("Secp256k1AddAssign", 17),
    ("Secp256k1DoubleAssign", 17),
    ("Secp256k1Decompress", 17),
    ("Secp256r1AddAssign", 17),
    ("Secp256r1DoubleAssign", 17),
    ("Secp256r1Decompress", 17),
    ("Bn254AddAssign", 17),
    ("Bn254DoubleAssign", 17),
    ("Bls12381AddAssign", 17),
    ("Bls12381DoubleAssign", 17),
    ("Bls12381Decompress", 17),
    ("Bn254FpOp", 17),
    ("Bn254Fp2AddSub", 17),
    ("Bn254Fp2Mul", 17),
    ("Bls381FpOp", 17),
    ("Bls381Fp2AddSub", 17),
    ("Bls381Fp2Mul", 17),
    ("Secp256k1FpOp", 17),
    // 1 row per event, but not in `tail_rows_and_width`, so the split keeps the hardware-tier
    // threshold for them and a block holds exactly that many events.
    ("Poseidon2Permute", 15),
    ("EdAddAssign", 12),
    ("EdDecompress", 12),
    ("Bls12381G2AddAssign", 12),
    ("Bls12381G2DoubleAssign", 12),
    // A row per round, the split's full block (`blake2b::ROUNDS_PER_BLOCK_LOG`); the control
    // sibling a row per call, its own cap (`blake2b::CALLS_PER_BLOCK_LOG`).
    ("Blake2bRound", 19),
    ("Blake2bControl", 14),
];

/// The heights `MemoryUnaligned` takes in a core shape, smallest first: a chunk proves its
/// misaligned loads and stores on the smallest that holds them, so each ladder row is in the
/// whitelist once per height up to its own (`MLE_CORE_LADDER`).
///
/// A guest built with `+unaligned-scalar-mem` makes them by the hundred thousand: the reth guest
/// of the EF p99 benchmark has a median of 65,000-95,000 a CPU chunk and at most 326,000 on four
/// blocks, most of them reading 32-byte hashes out of RLP at odd offsets. A guest built without it
/// makes next to none, and stays at 2^10. Rounded up to these five heights, a chunk pads 0.4% of
/// its cells, against 0.3% for every power of two.
pub const MLE_MEMORY_UNALIGNED_LOG_HEIGHTS: &[usize] = &[10, 16, 17, 18, 19];

/// The most rows `MemoryUnaligned` has in a core shape, the catch-all's height: the chunk split
/// closes a CPU chunk once it holds this many misaligned loads and stores
/// (`ChunkSplitConfig::misaligned_threshold`). Its 28 interactions a row add 28 x 2^19, 0.027 x
/// 2^29, to a row's TI.
pub const MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT: usize = 19;

/// The floor every present air pads to: `2^l_skip` rows, the smallest the MLE prover packs.
pub const MLE_MIN_LOG_HEIGHT: usize = 4;

/// `MemoryLocal` in a CPU chunk: its local-memory traffic scales with the instruction count.
pub const MEMORY_LOCAL_CPU_LOG_HEIGHT: usize = 22;

/// The log2 height of the Global AIR in every shape: the tables describe the production stacked
/// height (2^23), where the machine proves the Global AIR at
/// `pico_mle_core::global_logup::global_log_height` = 2^22 whatever the chunk's event count. At
/// another stacked height the machine pads the Global AIR to that height's own fixed value,
/// regardless of the entry a shape carries.
pub const MLE_GLOBAL_LOG_HEIGHT: usize = pico_mle_core::global_logup::MAX_GLOBAL_LOG_HEIGHT;

/// `MemoryLocal` in a deferred chunk: the ceiling the Global table puts on it. A local entry
/// raises up to two cross-chunk events and a row holds `LOCAL_MEMORY_DATAPAR = 4` entries, so
/// `ceil((2^MLE_GLOBAL_LOG_HEIGHT / 2) / LOCAL_MEMORY_DATAPAR)` rows.
pub const MEMORY_LOCAL_DEFERRED_LOG_HEIGHT: usize = MLE_GLOBAL_LOG_HEIGHT - 3;

/// Bucketed log2 height of the program's preprocessed table (and its main multiplicity trace —
/// the two must agree). Bucketing it makes the RISC-V vk's preprocessed GEOMETRY app-independent,
/// which is what lets two guest programs share one lean vk pre-hash.
///
/// Machine-wide, not per-shape: `Program::fixed_log2_rows` reads it off the program, so every
/// shape gets the same value. 2^20 is the reth guest's natural height (its 2^19..2^20
/// instructions pad to exactly this), and fib is far below it. The table's 28 preprocessed
/// columns are stacked at this height in EVERY chunk (2^23 stacked rows), so the two notches
/// down from 2^22 take 10.5 columns off every chunk's stacked width; a guest above 2^20
/// instructions stops at `with_mle_preprocessed_shape` with the number to raise, and raising it
/// rebuilds the whitelist.
pub const MLE_RISCV_PROGRAM_LOG_HEIGHT: usize = 20;

/// The core family's canonical presence set: the chips a bucketed CPU chunk declares present
/// whatever its opcode mix. Every entry is CPU-driven, so it can only ever appear in a CPU
/// chunk, and every one of them has a `MLE_RISCV_MAIN_LOG_HEIGHTS` entry.
///
/// Declaring them rather than deriving them from events is what collapses the whitelist's core
/// presence factor from one shape per subset (2^14 of them, since ten ALU chips, both memory
/// chips, the riscv syscall receiver and Ecall are each event-gated) to one. A chip with no
/// events costs `2^l_skip` rows of all-padding trace: measured at +0.0003 ms for the widest of
/// them and under 0.005 ms for the whole set, against a chunk in the hundreds of ms.
///
/// Deferred chunks are NOT covered: a precompile record carries exactly one compute kind and a
/// memory record carries MemoryFinalize (and MemoryInitialize on the last one), so their presence
/// already follows from the chunk kind and position. They keep the event-driven set.
pub const MLE_CORE_CANONICAL_PRESENCE: &[&str] = &[
    "Cpu",
    "Add",
    "Sub",
    "Mul",
    "Bitwise",
    "LessThan",
    "ShiftLeft",
    "ShiftRight",
    "DivRem",
    "Addw",
    "Subw",
    "MemoryLocal",
    "MemoryReadWrite",
    "MemoryUnaligned",
    "SyscallRiscv",
    "Ecall",
    "Global",
    "Byte",
    "Program",
];

/// Whether `chip_name` is declared present in every bucketed CPU chunk
/// (see [`MLE_CORE_CANONICAL_PRESENCE`]).
pub fn is_core_canonical(chip_name: &str) -> bool {
    MLE_CORE_CANONICAL_PRESENCE.contains(&chip_name)
}

/// The catch-all entry for `chip_name` in a chunk of the given kind. Panics for unknown chips —
/// every chip that can be active in the MLE RISC-V machine must have an entry.
pub fn bucket_log_height(chip_name: &str, is_cpu_chunk: bool) -> usize {
    if chip_name == "MemoryLocal" {
        return if is_cpu_chunk {
            MEMORY_LOCAL_CPU_LOG_HEIGHT
        } else {
            MEMORY_LOCAL_DEFERRED_LOG_HEIGHT
        };
    }
    MLE_RISCV_MAIN_LOG_HEIGHTS
        .iter()
        .find(|(n, _)| *n == chip_name)
        .map(|(_, log)| *log)
        .unwrap_or_else(|| {
            panic!("chip `{chip_name}` has no MLE bucket entry (MLE_RISCV_MAIN_LOG_HEIGHTS)")
        })
}

/// The core family's height ladder, fitted to the CPU chunks of the reth guest on the 80-block
/// p99 corpus (3,047 chunks, probed 2026-11-13), every fourth block by number held out: 24
/// classes by agglomerative clustering (a class is the componentwise maximum of its members)
/// and nine envelope rows, which are no fitted class. Three of them come from a coarse 3-class
/// clustering of the same chunks, with headroom on the cheap chips; the other six are wider
/// still, for chunks beyond the corpus (row 30 holds a G1MSM chunk of block 26180455). No chip
/// sits below a floor in any row: Subw, Addw and DivRem stay at 2^10 or more, since a recent
/// block can carry 2^7 Subw rows in one chunk where the corpus has none.
/// The rows from [`MLE_CORE_FITTED_ROWS`] on were added after the fit, for chunks of EF guests
/// and word-op heavy programs that no fitted row holds.
///
/// The rows are priced by what a chunk costs to prove on them, regressed on the same probe:
/// 0.344 ms per million cells and 0.026 ms per million GKR leaves (2^m, m the bit length of
/// TI = sum(interactions x height)), with the interaction counts and widths of a real keygen.
/// The Global AIR is at 2^22 rows in every chunk, which alone puts 70% of the corpus's CPU
/// chunks past TI = 2^28 at their natural heights. Under this price a CPU chunk costs +1.8%
/// over its natural heights, on the fit set and on the held-out blocks alike.
///
/// A chunk takes the FIRST entry that dominates it componentwise, and the rows sit
/// cheapest-first by that price, so the first dominating row is the cheapest one. The rows added
/// after the fit sit last, so they take only chunks no other row holds. The catch-all
/// (not listed here, it is [`MLE_RISCV_MAIN_LOG_HEIGHTS`]) comes last. Every row keeps TI under
/// 2^29: at 2^29 the GKR size m goes from 29 to 30 and the leaf buffer no longer fits a card,
/// so a row past it would be CPU-only (`core_ladder_rows_stay_under_the_gpu_line`).
///
/// Under canonical presence a class is one whole height vector, hence one whitelist entry -- K
/// is bounded by keygen time, not by the whitelist budget.
///
/// Byte is a fixed-height table, Program is machine-wide and Global proves at one fixed height,
/// so all three are the same in every row.
///
/// `MemoryUnaligned` is the one chip a row does not pin: its entry is the most the row holds, and
/// a chunk on the row takes the smallest of [`MLE_MEMORY_UNALIGNED_LOG_HEIGHTS`] that holds its
/// misaligned accesses (`core_rungs`). The fit and the prices above are at 2^10, from guests that
/// made none; every row takes 2^19 but row 32, already at 0.98 x 2^29, which stops at 2^18.
///
/// The envelope rows sit at [`MLE_CORE_ENVELOPE_ROWS`]; sorted by price they land between the
/// classes, so a chunk a class holds can still take an envelope row that is cheaper and also
/// holds it. The fitting tools and the corpus are not part of this repository.
pub const MLE_CORE_LADDER: &[&[(&str, usize)]] = &[
    // row 0: 21 fit-set chunks; 27 corpus chunks; 168 ms; TI 0.25 x 2^29
    &[
        ("Cpu", 22),
        ("MemoryReadWrite", 20),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 20),
        ("Sub", 15),
        ("LessThan", 19),
        ("Bitwise", 19),
        ("ShiftLeft", 18),
        ("ShiftRight", 17),
        ("Mul", 13),
        ("Addw", 12),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 12),
        ("Ecall", 12),
        ("MemoryLocal", 16),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 1: 12 fit-set chunks; 12 corpus chunks; 206 ms; TI 0.30 x 2^29
    &[
        ("Cpu", 22),
        ("MemoryReadWrite", 21),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 16),
        ("LessThan", 20),
        ("Bitwise", 19),
        ("ShiftLeft", 18),
        ("ShiftRight", 18),
        ("Mul", 13),
        ("Addw", 13),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 13),
        ("Ecall", 13),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 2: 140 fit-set chunks; 201 corpus chunks; 320 ms; TI 0.48 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 14),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 3: 60 fit-set chunks; 77 corpus chunks; 338 ms; TI 0.50 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 16),
        ("LessThan", 20),
        ("Bitwise", 19),
        ("ShiftLeft", 17),
        ("ShiftRight", 16),
        ("Mul", 16),
        ("Addw", 15),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 4: 52 fit-set chunks; 73 corpus chunks; 346 ms; TI 0.50 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 22),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 13),
        ("Addw", 15),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 13),
        ("Ecall", 13),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 5: 304 fit-set chunks; 420 corpus chunks; 347 ms; TI 0.50 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 16),
        ("Addw", 13),
        ("Subw", 10),
        ("DivRem", 12),
        ("SyscallRiscv", 12),
        ("Ecall", 12),
        ("MemoryLocal", 15),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 6: 35 fit-set chunks; 48 corpus chunks; 349 ms; TI 0.52 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 21),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 17),
        ("Addw", 18),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 7: 39 fit-set chunks; 50 corpus chunks; 353 ms; TI 0.54 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 19),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 8: 295 fit-set chunks; 380 corpus chunks; 357 ms; TI 0.51 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 15),
        ("Subw", 10),
        ("DivRem", 12),
        ("SyscallRiscv", 15),
        ("Ecall", 15),
        ("MemoryLocal", 16),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 9: 141 fit-set chunks; 210 corpus chunks; 361 ms; TI 0.52 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 18),
        ("Addw", 15),
        ("Subw", 10),
        ("DivRem", 13),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 16),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 10: 238 fit-set chunks; 331 corpus chunks; 362 ms; TI 0.53 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 17),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 12),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 11: 28 fit-set chunks; 31 corpus chunks; 362 ms; TI 0.53 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 16),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 18),
        ("ShiftRight", 17),
        ("Mul", 16),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 19),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 12: 147 fit-set chunks; 237 corpus chunks; 364 ms; TI 0.52 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 14),
        ("Subw", 10),
        ("DivRem", 13),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 16),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 13: 103 fit-set chunks; 137 corpus chunks; 368 ms; TI 0.53 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 15),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 14: 36 fit-set chunks; 35 corpus chunks; 372 ms; TI 0.55 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 18),
        ("Addw", 15),
        ("Subw", 10),
        ("DivRem", 11),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 15: 117 fit-set chunks; 144 corpus chunks; 374 ms; TI 0.54 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 18),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 13),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 16: 122 fit-set chunks; 167 corpus chunks; 376 ms; TI 0.54 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 15),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 17: 69 fit-set chunks; 89 corpus chunks; 379 ms; TI 0.54 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 22),
        ("Bitwise", 19),
        ("ShiftLeft", 21),
        ("ShiftRight", 21),
        ("Mul", 12),
        ("Addw", 13),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 10),
        ("Ecall", 10),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 18: 113 fit-set chunks; 129 corpus chunks; 380 ms; TI 0.55 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 17),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 19: 49 fit-set chunks; 62 corpus chunks; 384 ms; TI 0.56 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 18),
        ("Addw", 15),
        ("Subw", 10),
        ("DivRem", 14),
        ("SyscallRiscv", 15),
        ("Ecall", 15),
        ("MemoryLocal", 17),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 20: 36 fit-set chunks; 54 corpus chunks; 385 ms; TI 0.56 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 21),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 17),
        ("Addw", 17),
        ("Subw", 10),
        ("DivRem", 14),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 21: 27 fit-set chunks; 39 corpus chunks; 396 ms; TI 0.59 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 19),
        ("Addw", 17),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 16),
        ("Ecall", 16),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 22: envelope row for chunks beyond the corpus; 0 corpus chunks; 419 ms; TI 0.66 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 20),
        ("Addw", 18),
        ("Subw", 16),
        ("DivRem", 17),
        ("SyscallRiscv", 19),
        ("Ecall", 18),
        ("MemoryLocal", 16),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 23: envelope row; 1 corpus chunks; 422 ms; TI 0.65 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 19),
        ("Addw", 18),
        ("Subw", 12),
        ("DivRem", 17),
        ("SyscallRiscv", 20),
        ("Ecall", 19),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 24: envelope row for chunks beyond the corpus; 0 corpus chunks; 425 ms; TI 0.67 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 19),
        ("Addw", 18),
        ("Subw", 10),
        ("DivRem", 18),
        ("SyscallRiscv", 19),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 25: 28 fit-set chunks; 33 corpus chunks; 435 ms; TI 0.64 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 22),
        ("Bitwise", 21),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 18),
        ("Addw", 17),
        ("Subw", 10),
        ("DivRem", 16),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 26: 47 fit-set chunks; 60 corpus chunks; 443 ms; TI 0.63 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 23),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 10),
        ("SyscallRiscv", 18),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 27: envelope row for chunks beyond the corpus; 0 corpus chunks; 484 ms; TI 0.74 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 22),
        ("Bitwise", 20),
        ("ShiftLeft", 21),
        ("ShiftRight", 21),
        ("Mul", 19),
        ("Addw", 19),
        ("Subw", 15),
        ("DivRem", 18),
        ("SyscallRiscv", 19),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 28: envelope row for chunks beyond the corpus; 0 corpus chunks; 526 ms; TI 0.80 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 23),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 21),
        ("Bitwise", 21),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 20),
        ("Addw", 17),
        ("Subw", 10),
        ("DivRem", 14),
        ("SyscallRiscv", 19),
        ("Ecall", 18),
        ("MemoryLocal", 19),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 29: envelope row; 0 corpus chunks; 535 ms; TI 0.75 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 23),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 21),
        ("Sub", 19),
        ("LessThan", 22),
        ("Bitwise", 20),
        ("ShiftLeft", 21),
        ("ShiftRight", 21),
        ("Mul", 18),
        ("Addw", 17),
        ("Subw", 12),
        ("DivRem", 14),
        ("SyscallRiscv", 20),
        ("Ecall", 19),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 30: envelope row for chunks beyond the corpus; 0 corpus chunks; 537 ms; TI 0.79 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 23),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 22),
        ("Bitwise", 21),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 19),
        ("Addw", 18),
        ("Subw", 16),
        ("DivRem", 16),
        ("SyscallRiscv", 19),
        ("Ecall", 18),
        ("MemoryLocal", 19),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 31: envelope row; 0 corpus chunks; 551 ms; TI 0.96 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 22),
        ("Bitwise", 21),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 20),
        ("Addw", 19),
        ("Subw", 12),
        ("DivRem", 20),
        ("SyscallRiscv", 20),
        ("Ecall", 19),
        ("MemoryLocal", 19),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 32: envelope row for chunks beyond the corpus; 0 corpus chunks; 572 ms; TI 0.98 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", 18), // 2^19 would take the row past TI = 2^29
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 22),
        ("Bitwise", 21),
        ("ShiftLeft", 21),
        ("ShiftRight", 21),
        ("Mul", 20),
        ("Addw", 18),
        ("Subw", 10),
        ("DivRem", 20),
        ("SyscallRiscv", 20),
        ("Ecall", 19),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 33 (added): row 27 with Bitwise at 2^22, for hash-table-heavy guests (EF ethrex);
    // TI under 2^29.
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 20),
        ("LessThan", 22),
        ("Bitwise", 22),
        ("ShiftLeft", 21),
        ("ShiftRight", 21),
        ("Mul", 19),
        ("Addw", 19),
        ("Subw", 15),
        ("DivRem", 18),
        ("SyscallRiscv", 19),
        ("Ecall", 18),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 34 (added): Addw at 2^21 and Subw at 2^19, for word-op heavy programs (byte-offset
    // memcpy-style loops); TI under 2^29.
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("MemoryUnaligned", MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 17),
        ("Addw", 21),
        ("Subw", 19),
        ("DivRem", 11),
        ("SyscallRiscv", 16),
        ("Ecall", 16),
        ("MemoryLocal", 18),
        ("Global", MLE_GLOBAL_LOG_HEIGHT),
        ("Byte", 17),
        ("Program", 20),
    ],
];

/// The number of [`MLE_CORE_LADDER`] rows from the fit; the rows after them were added for chunks
/// the fit never saw.
pub const MLE_CORE_FITTED_ROWS: usize = 33;

/// The rows of [`MLE_CORE_LADDER`] that are envelope rows (three from the coarse 3-class
/// clustering with headroom, six for chunks beyond the corpus) rather than fitted classes; the
/// run log names them so a run's cost can be attributed to them.
pub const MLE_CORE_ENVELOPE_ROWS: &[usize] = &[22, 23, 24, 27, 28, 29, 30, 31, 32];

/// One precompile-family shape: the compute kind at a log height, its control sibling if it has
/// one, and the companions the kind's event count drives. Byte and Program are pinned
/// machine-wide and are not carried here.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MlePrecompileShape {
    pub kind: String,
    pub kind_log_height: usize,
    pub control: Option<(String, usize)>,
    pub syscall_precompile: usize,
    pub memory_local: usize,
}

/// The control sibling a compute kind emits alongside itself, one row per parent event.
fn precompile_control_sibling(kind: &str) -> Option<&'static str> {
    match kind {
        "ShaCompress" => Some("ShaCompressControl"),
        "ShaExtend" => Some("ShaExtendControl"),
        "KeccakPermute" => Some("KeccakControl"),
        "Blake2bRound" => Some("Blake2bControl"),
        _ => None,
    }
}

/// The height the BLAKE2b control chip and the precompile syscall table pad to beside a round
/// chip of `2^round_log`: `2^min(round_log, CALLS_PER_BLOCK_LOG)`, which holds the record's calls
/// (each runs at least one round, and the split closes a block at `2^CALLS_PER_BLOCK_LOG`
/// calls). A call runs a caller-chosen number of rounds, so the calls are a second free variable
/// beside the rounds; pinning their height to the rounds' keeps the whitelist to one control
/// height per round height, at the cost of padding a record of few long calls.
pub fn blake2b_call_log_height(round_log: usize) -> usize {
    round_log.clamp(
        MLE_MIN_LOG_HEIGHT,
        crate::chips::precompiles::blake2b::CALLS_PER_BLOCK_LOG,
    )
}

/// Memory+Regional lookups a chip's air declares per row, counted off the air itself.
///
/// `get_all_precompile_chips` reports this for the compute kinds only, and reports zero for
/// KeccakPermute because that chip raises no memory lookups of its own -- they live on its
/// KeccakControl sibling, which the pool excludes. Counting by name covers both.
///
/// Every chip is counted on the first call: building the chips takes about 80 ms, and the
/// precompile enumeration asks once per kind and per control sibling.
fn memory_lookups_per_row(chip_name: &str) -> usize {
    use crate::{
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::{
            chip::ChipBehavior,
            lookup::{LookupScope, LookupType},
        },
    };
    static COUNTS: std::sync::OnceLock<BTreeMap<String, usize>> = std::sync::OnceLock::new();
    COUNTS
        .get_or_init(|| {
            let mut counts = BTreeMap::new();
            for chip in RiscvChipType::<Kb>::all_chips() {
                counts.entry(chip.name()).or_insert_with(|| {
                    chip.get_looking()
                        .iter()
                        .chain(chip.get_looked())
                        .filter(|lookup| {
                            lookup.kind == LookupType::Memory
                                && lookup.scope == LookupScope::Regional
                        })
                        .count()
                });
            }
            counts
        })
        .get(chip_name)
        .copied()
        .unwrap_or_else(|| panic!("no chip named `{chip_name}` in the RISC-V machine"))
}

/// The event counts whose kind trace pads to exactly `2^kind_log_height`: `(n_lo, n_hi)`, or
/// `None` when no count does. The rows are `precompile_kind_rows`, which grows with `n`, so the
/// counts form one interval, found by bisection over `[1, 2^kind_log_height]` (a trace holds at
/// least a row per event).
pub(crate) fn kind_event_window(kind: &str, kind_log_height: usize) -> Option<(usize, usize)> {
    use crate::instances::compiler::shapes::riscv_shape::precompile_kind_rows;
    let log = |n: usize| {
        (precompile_kind_rows(kind, n)
            .max(1)
            .next_power_of_two()
            .ilog2() as usize)
            .max(MLE_MIN_LOG_HEIGHT)
    };
    // The first `n` in `[lo, hi]` where `pred` holds, `pred` false-then-true; `hi + 1` if none.
    let first = |mut lo: usize, mut hi: usize, pred: &dyn Fn(usize) -> bool| {
        hi += 1;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if pred(mid) {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    };
    let max = 1usize << kind_log_height;
    let n_hi = first(1, max, &|n| log(n) > kind_log_height) - 1;
    let n_lo = first(1, max, &|n| log(n) >= kind_log_height);
    (n_lo >= 1 && n_lo <= n_hi).then_some((n_lo, n_hi))
}

/// Every shape the precompile family admits.
///
/// A precompile chunk has TWO free variables, not one. The event count `n` of the compute kind
/// drives the kind's own height (`precompile_kind_rows`: `n * rows_per_event`, or the sliced Keccak's
/// slot layout) and, one row per event, its syscall and
/// control siblings. But MemoryLocal counts the DISTINCT ADDRESSES the chunk touches, which
/// address locality decides, not `n`: the corpus pins no per-event constant that explains it,
/// and for Uint256MulMod the bracket its rows imply is empty. So MemoryLocal is swept, bounded
/// above by what the airs can possibly raise -- `n * (rows_per_event * lookups_per_row +
/// control_lookups_per_row)` -- and below by the `2^l_skip` floor.
///
/// Everything else follows. Global holds the chunk's cross-chunk events, one or two per local
/// entry and one per syscall, at [`MLE_GLOBAL_LOG_HEIGHT`] in every shape, so it adds no axis:
/// it only rules out the points whose fewest events do not fit the table.
///
/// Heights are capped by the family catch-all, which bounds every reachable chunk; a point above
/// it is unreachable and is dropped rather than clamped, so nothing here exceeds it.
pub fn mle_precompile_shapes() -> Vec<MlePrecompileShape> {
    use crate::{
        instances::{
            chiptype::riscv_chiptype::RiscvChipType,
            compiler::shapes::riscv_shape::precompile_rows_per_event,
        },
        primitives::consts::LOCAL_MEMORY_DATAPAR,
    };

    let log2_ceil = |n: u128| -> usize {
        let n = n.max(1);
        let bits = 128 - (n - 1).leading_zeros() as usize;
        bits.max(MLE_MIN_LOG_HEIGHT)
    };
    let mut out = Vec::new();
    // The pool is the FRI chip set; only the kinds the MLE riscv air table lists are shapes here,
    // so a chip that exists in the pool but not in the machine stays out of the whitelist.
    for (kind, _) in RiscvChipType::<Kb>::get_all_precompile_chips()
        .into_iter()
        .filter(|(kind, _)| super::riscv::air_id_for(kind).is_some())
    {
        if kind == "Blake2bRound" {
            out.extend(blake2b_precompile_shapes());
            continue;
        }
        let rows_per_event = precompile_rows_per_event(&kind) as u128;
        let control = precompile_control_sibling(&kind);
        // The most memory lookups one event can raise: its rows on the compute air, plus the one
        // row its control sibling adds. Real chunks raise fewer, because repeated touches of one
        // address collapse into a single MemoryLocal entry.
        let mem_per_event = rows_per_event * memory_lookups_per_row(&kind) as u128
            + control.map_or(0, |c| memory_lookups_per_row(c) as u128);
        let kind_cap = bucket_log_height(&kind, false);
        let syscall_cap = bucket_log_height("SyscallPrecompile", false);
        let memory_local_cap = bucket_log_height("MemoryLocal", false);
        let global_rows = 1u128 << bucket_log_height("Global", false);
        let control_cap = control.map(|c| bucket_log_height(c, false));

        for kind_log_height in MLE_MIN_LOG_HEIGHT..=kind_cap {
            // Event counts this kind height admits: the kind air pads its rows
            // (`precompile_kind_rows`) up to `2^kind_log_height`, so `n` spans a factor of two
            // (clipped at the floor). A height the layout never lands on (the sliced Keccak's
            // 2^9) admits none.
            let Some((n_lo, n_hi)) = kind_event_window(&kind, kind_log_height) else {
                continue;
            };
            let (n_lo, n_hi) = (n_lo as u128, n_hi as u128);
            // Two values for a window of a factor of two; the sliced Keccak's 2^10 window, which
            // takes the counts 2^9 would have held, spans a factor of four.
            for syscall in log2_ceil(n_lo)..=log2_ceil(n_hi) {
                if syscall > syscall_cap || control_cap.is_some_and(|c| syscall > c) {
                    continue;
                }
                // `n` restricted to this syscall height, intersected with the kind's window.
                let s_hi = (1u128 << syscall).min(n_hi);
                let s_lo = if syscall == MLE_MIN_LOG_HEIGHT {
                    n_lo
                } else {
                    ((1u128 << (syscall - 1)) + 1).max(n_lo)
                };
                if s_hi < s_lo {
                    continue;
                }
                let local_hi = s_hi * mem_per_event;
                for memory_local in MLE_MIN_LOG_HEIGHT..=memory_local_cap {
                    // Raw local entries this MemoryLocal height admits, clipped to what the airs
                    // can raise at all.
                    let l_hi =
                        ((1u128 << memory_local) * LOCAL_MEMORY_DATAPAR as u128).min(local_hi);
                    let l_lo = if memory_local == MLE_MIN_LOG_HEIGHT {
                        1
                    } else {
                        (1u128 << (memory_local - 1)) * LOCAL_MEMORY_DATAPAR as u128 + 1
                    };
                    if l_hi < l_lo {
                        continue;
                    }
                    // The fewest cross-chunk events the point raises: one per syscall, and
                    // one per local entry when every entry is a first touch (any other raises
                    // two). A point that cannot fit the Global table is unreachable.
                    if l_lo + s_lo > global_rows {
                        continue;
                    }
                    out.push(MlePrecompileShape {
                        kind: kind.clone(),
                        kind_log_height,
                        control: control.map(|c| (c.to_string(), syscall)),
                        syscall_precompile: syscall,
                        memory_local,
                    });
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The BLAKE2b family's shapes. The round chip's rows are the record's rounds and its control
/// sibling's the calls, and a call runs a caller-chosen number of rounds, so the two heights are
/// independent: the control chip and the syscall table take [`blake2b_call_log_height`] of the
/// round height, which `select_riscv_shape` pads them to, and MemoryLocal is swept as for every
/// kind, up to what `2^calls` calls can touch. Global is at [`MLE_GLOBAL_LOG_HEIGHT`] here too, so
/// it only rules out the points whose fewest events do not fit the table.
fn blake2b_precompile_shapes() -> Vec<MlePrecompileShape> {
    use crate::primitives::consts::LOCAL_MEMORY_DATAPAR;
    const KIND: &str = "Blake2bRound";
    const CONTROL: &str = "Blake2bControl";
    // The round chip raises no memory lookups; a call's are its control row's, which bound the
    // local entries it adds.
    let mem_per_call = memory_lookups_per_row(CONTROL) as u128;
    let memory_local_cap = bucket_log_height("MemoryLocal", false);
    let global_rows = 1u128 << bucket_log_height("Global", false);
    let mut out = Vec::new();
    for kind_log_height in MLE_MIN_LOG_HEIGHT..=bucket_log_height(KIND, false) {
        let calls_log = blake2b_call_log_height(kind_log_height);
        if calls_log > bucket_log_height("SyscallPrecompile", false)
            || calls_log > bucket_log_height(CONTROL, false)
        {
            continue;
        }
        let local_hi = (1u128 << calls_log) * mem_per_call;
        for memory_local in MLE_MIN_LOG_HEIGHT..=memory_local_cap {
            let l_hi = ((1u128 << memory_local) * LOCAL_MEMORY_DATAPAR as u128).min(local_hi);
            let l_lo = if memory_local == MLE_MIN_LOG_HEIGHT {
                1
            } else {
                (1u128 << (memory_local - 1)) * LOCAL_MEMORY_DATAPAR as u128 + 1
            };
            // The fewest cross-chunk events the point raises, one call's and one per local entry
            // (every entry a first touch), must fit the Global table.
            if l_hi < l_lo || l_lo + 1 > global_rows {
                continue;
            }
            out.push(MlePrecompileShape {
                kind: KIND.to_string(),
                kind_log_height,
                control: Some((CONTROL.to_string(), calls_log)),
                syscall_precompile: calls_log,
                memory_local,
            });
        }
    }
    out
}

/// Every riscv shape the whitelist admits, labelled by family, in a stable order.
///
/// This is the enumeration `build_vk_map` keys the whitelist on and the tier probe walks: the
/// core ladder with its catch-all behind it, the memory family's free product, and the
/// precompile family's per-kind sweep. Byte, Program and Global are pinned machine-wide and
/// appear in every shape.
pub fn mle_riscv_shapes() -> Vec<(String, Vec<(String, usize)>)> {
    let byte = ("Byte".to_string(), bucket_log_height("Byte", false));
    let program = ("Program".to_string(), bucket_log_height("Program", false));
    let global = ("Global".to_string(), bucket_log_height("Global", false));
    let mut out = Vec::new();

    for (i, unaligned, shape) in core_rungs() {
        out.push((format!("core:class{i}:unaligned{unaligned}"), shape));
    }
    out.push((
        "core:catch-all".to_string(),
        MLE_CORE_CANONICAL_PRESENCE
            .iter()
            .map(|n| (n.to_string(), bucket_log_height(n, true)))
            .collect(),
    ));

    // Memory: MemoryInitialize and MemoryFinalize each absent or anywhere in range. Both absent
    // is not a memory shape at all.
    let init_cap = bucket_log_height("MemoryInitialize", false);
    let final_cap = bucket_log_height("MemoryFinalize", false);
    for init in (MLE_MIN_LOG_HEIGHT..=init_cap).map(Some).chain([None]) {
        for fin in (MLE_MIN_LOG_HEIGHT..=final_cap).map(Some).chain([None]) {
            if init.is_none() && fin.is_none() {
                continue;
            }
            let mut shape = vec![byte.clone(), program.clone()];
            if let Some(h) = init {
                shape.push(("MemoryInitialize".to_string(), h));
            }
            if let Some(h) = fin {
                shape.push(("MemoryFinalize".to_string(), h));
            }
            shape.push(global.clone());
            out.push((
                format!(
                    "memory:{}/{}",
                    init.map_or("-".to_string(), |h| h.to_string()),
                    fin.map_or("-".to_string(), |h| h.to_string())
                ),
                shape,
            ));
        }
    }

    for s in mle_precompile_shapes() {
        let mut shape = vec![
            byte.clone(),
            program.clone(),
            (s.kind.clone(), s.kind_log_height),
            ("SyscallPrecompile".to_string(), s.syscall_precompile),
            ("MemoryLocal".to_string(), s.memory_local),
            global.clone(),
        ];
        if let Some((name, h)) = s.control.clone() {
            shape.push((name, h));
        }
        shape.extend(
            crate::instances::compiler::shapes::riscv_shape::precompile_tables(&s.kind)
                .iter()
                .map(|(name, h)| (name.to_string(), *h)),
        );
        out.push((
            format!(
                "precompile:{}:{}/{}/{}",
                s.kind, s.kind_log_height, s.syscall_precompile, s.memory_local
            ),
            shape,
        ));
    }
    out
}

/// A digest of the shape config that shapes the whitelist's leaves: every riscv shape the whitelist
/// admits, the convert ladder rows, the group nodes' row, the combine and compress tier tables,
/// the largest group and the image tiers of the global LogUp (its nodes' leaves), and the Merkle
/// depth. The vk-map artifact carries it, and loading an artifact under a binary whose
/// config digests differently is refused -- a whitelist built from one shape config must not be
/// used to prove under another, since the enumeration order, these tables and the depth all shape
/// the leaves.
///
/// The embed row is left out: the embed key is no leaf, so its row moves only the embed
/// key, which the soundness manifest records and the artifact unit test holds against this binary.
///
/// The stacked height the riscv machine runs at is left out too, though the image tiers in use
/// and the group nodes' table follow it: an artifact is built at the height the prover ships
/// with (`mle_build_vk_map` warns otherwise). One built at another height digests the same and
/// loads, and then lists none of the keys a prover derives: its proofs stop at the first key
/// check, and the artifact unit test fails on it.
///
/// Field-native: each shape is its `(air id, log height)` pairs sorted by air id, length-prefixed;
/// then the convert row count and each tier table's heights in table order, length-prefixed;
/// then the largest group, the lowest and the highest image tier, and the depth. Sponge-hashed
/// with the same padding-free sponge the leaves use.
pub fn mle_shape_config_digest() -> [Kb; 8] {
    use crate::mle::machine::{exe::sponge_hash, riscv::air_name, vk_map::MLE_VK_MERKLE_DEPTH};
    use pico_mle_core::global_logup;
    // The riscv air table is position-indexed and contiguous, so walking ids until the first
    // gap covers exactly the machine's airs.
    let ids: BTreeMap<&str, u32> = (0u32..)
        .map_while(|id| air_name(id as usize).map(|n| (n, id)))
        .collect();
    let mut pre: Vec<Kb> = Vec::new();
    let shapes = mle_riscv_shapes();
    pre.push(Kb::from_u32(shapes.len() as u32));
    for (_, shape) in &shapes {
        let mut pairs: Vec<(u32, u32)> = shape
            .iter()
            .map(|(n, h)| (ids[n.as_str()], *h as u32))
            .collect();
        pairs.sort_unstable();
        pre.push(Kb::from_u32(pairs.len() as u32));
        for (id, h) in pairs {
            pre.push(Kb::from_u32(id));
            pre.push(Kb::from_u32(h));
        }
    }
    pre.push(Kb::from_u32(MLE_RECURSION_CONVERT_LADDER.len() as u32));
    for table in MLE_RECURSION_CONVERT_LADDER.iter().copied().chain([
        MLE_RECURSION_GROUP_NODE_LOG_HEIGHTS,
        MLE_RECURSION_COMBINE_LOG_HEIGHTS,
        MLE_RECURSION_COMPRESS_LOG_HEIGHTS,
    ]) {
        pre.push(Kb::from_u32(table.len() as u32));
        pre.extend(table.iter().map(|(_, h)| Kb::from_u32(*h as u32)));
    }
    // The global LogUp's nodes: a group node for every group size, an image node for every
    // image tier. Another largest group or another range of tiers is another set of leaves.
    pre.push(Kb::from_u32(global_logup::MAX_GROUP_LEN as u32));
    pre.push(Kb::from_u32(global_logup::MIN_IMAGE_LOG_HEIGHT as u32));
    pre.push(Kb::from_u32(global_logup::MAX_GLOBAL_LOG_HEIGHT as u32));
    pre.push(Kb::from_u32(MLE_VK_MERKLE_DEPTH as u32));
    sponge_hash(&pre)
}

/// The natural row count of every air a record activates, without generating a trace.
///
/// This is what the ladder and the two enumerations are matched against, and it has to agree
/// row-for-row with what tracegen will produce -- a height that under-reports by one row gives a
/// shape the trace does not fit. So `record` must be the one tracegen reads, after
/// [`super::riscv::augmented_record`] has appended every chip's `extra_record` output: those
/// extras carry ALU events, not only byte lookups, and the emulator's raw counts fall short.
///
/// The per-chip counts come from the helpers the FRI shape system uses, plus `Ecall`, which
/// postdates them and carries one row per ecall instruction. Global is then overridden with
/// the event vector its generator actually reads, `global_lookup_events`, rather than the
/// derivation those helpers make of it: one row per event. The Global AIR proves at one fixed
/// height whatever this count, so the count only has to fit that height.
///
/// Byte and Program are left out: both are pinned machine-wide, so they never take part in a
/// match.
pub fn mle_natural_heights(record: &EmulationRecord) -> BTreeMap<String, usize> {
    use crate::instances::chiptype::riscv_chiptype::RiscvChipType;

    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    if record.is_cpu_chunk {
        out.extend(RiscvChipType::<Kb>::riscv_heights(record));
        out.insert("Ecall".to_string(), record.cpu_steps().ecalls().len());
        // `riscv_heights` reports the whole core set plus the memory pair, which a CPU chunk
        // does not carry.
        out.remove("MemoryInitialize");
        out.remove("MemoryFinalize");
    } else if !record.memory_initialize_events.is_empty()
        || !record.memory_finalize_events.is_empty()
    {
        out.extend(RiscvChipType::<Kb>::get_memory_init_final_heights(record));
        // Most memory records carry finalize events only: the finalize stream is bucketed on
        // its own and the initialize stream rides as one block on the last record, or on a
        // record of its own (`EmulationRecord::split`).
        out.retain(|_, rows| *rows > 0);
    } else {
        // A precompile chunk carries exactly one compute kind (`split` puts each kind in its own
        // record), its control sibling if it has one, and the shared companions.
        use crate::{
            instances::compiler::shapes::riscv_shape::{
                precompile_syscall_code, precompile_tables,
            },
            primitives::consts::LOCAL_MEMORY_DATAPAR,
        };
        for kind in precompile_kinds() {
            let Some((kind_rows, local_mem_events, _)) =
                RiscvChipType::<Kb>::get_precompile_heights(kind, record)
            else {
                continue;
            };
            let events = record
                .precompile_events
                .get_events(precompile_syscall_code(kind))
                .map_or(0, |events| events.len());
            if let Some(control) = precompile_control_sibling(kind) {
                out.insert(control.to_string(), events);
            }
            for (table, log) in precompile_tables(kind) {
                out.insert(table.to_string(), 1 << log);
            }
            out.insert(kind.clone(), kind_rows);
            out.insert("SyscallPrecompile".to_string(), events);
            out.insert(
                "MemoryLocal".to_string(),
                local_mem_events.div_ceil(LOCAL_MEMORY_DATAPAR),
            );
            out.insert("Global".to_string(), 2 * local_mem_events + events);
        }
    }
    // What the generator reads, whichever family: one Global row per event.
    if out.contains_key("Global") {
        out.insert("Global".to_string(), record.global_lookup_events.len());
    }
    out
}

/// [`mle_natural_heights`] read off the GPU preparer's `EventCounter`, which already holds
/// every count the device kernels size their traces from, extra-record events included. Row for
/// row what `mle_natural_heights` returns on the augmented record, without that path's record
/// clone and host extra-record pass, and without its walks over the events: a core chunk's table
/// is rebuilt from the counter and the history's ecall list; a memory chunk's from the two event vectors' lengths; a precompile chunk's from the counter's
/// per-kind event and local-memory counts; Global, the height extra-record output feeds, comes
/// from the counter in every family. `MLE_SHAPE_CROSSCHECK=1` asserts the
/// equality on every chunk (`prepare_chunk_shaped`).
#[cfg(feature = "cuda")]
pub fn mle_natural_heights_from_counter(
    record: &EmulationRecord,
    counter: &crate::instances::preparer::EventCounter,
) -> BTreeMap<String, usize> {
    use crate::primitives::consts::{
        ADD_DATAPAR, BITWISE_DATAPAR, DIVREM_DATAPAR, LOCAL_MEMORY_DATAPAR, LT_DATAPAR,
        MEMORY_RW_DATAPAR, MUL_DATAPAR, SLL_DATAPAR, SR_DATAPAR, SUB_DATAPAR,
    };
    if !record.is_cpu_chunk {
        // The deferred families, off the counter: `mle_natural_heights` walks every precompile
        // event's local memory accesses to count them, which on a keccak chunk is hundreds of
        // milliseconds on the preparer lane, while the packaging already counted exactly that
        // (`get_precompile_local_mem_len`, the same expression). Same map as the record walk,
        // row for row; `MLE_SHAPE_CROSSCHECK=1` asserts it.
        use crate::{
            instances::compiler::shapes::riscv_shape::{
                precompile_kind_rows, precompile_syscall_code, precompile_tables,
            },
            primitives::consts::LOCAL_MEMORY_DATAPAR,
        };
        let mut out: BTreeMap<String, usize> = BTreeMap::new();
        if !record.memory_initialize_events.is_empty() || !record.memory_finalize_events.is_empty()
        {
            // Most memory records carry finalize events only: the finalize stream is bucketed
            // on its own and the initialize stream rides as one block on the last record, or
            // on a record of its own (`EmulationRecord::split`).
            for (name, rows) in [
                ("MemoryInitialize", record.memory_initialize_events.len()),
                ("MemoryFinalize", record.memory_finalize_events.len()),
            ] {
                if rows > 0 {
                    out.insert(name.to_string(), rows);
                }
            }
        } else {
            // A precompile chunk carries exactly one compute kind (`split` puts each kind in
            // its own record), its control sibling if it has one, and the shared companions.
            for kind in precompile_kinds() {
                let code = precompile_syscall_code(kind);
                let events = record
                    .precompile_events
                    .get_events(code)
                    .map_or(0, |events| events.len());
                if events == 0 {
                    continue;
                }
                let local_mem_events = counter.get_precomplie_local_mem_event_num(code);
                if let Some(control) = precompile_control_sibling(kind) {
                    out.insert(control.to_string(), events);
                }
                for (table, log) in precompile_tables(kind) {
                    out.insert(table.to_string(), 1 << log);
                }
                out.insert(
                    kind.clone(),
                    precompile_kind_rows(kind, counter.get_precompile_kind_units(kind, code)),
                );
                out.insert("SyscallPrecompile".to_string(), events);
                out.insert(
                    "MemoryLocal".to_string(),
                    local_mem_events.div_ceil(LOCAL_MEMORY_DATAPAR),
                );
            }
        }
        // What the generator reads, whichever family: one Global row per event.
        out.insert("Global".to_string(), counter.num_global_lookup_events);
        return out;
    }
    // One row per ecall instruction: the history's ecall list.
    let ecalls = record.cpu_steps().ecalls().len();
    // `get_local_mem_events` chains the precompile local memory events (none in a CPU chunk)
    // and the CPU ones; the counter holds both counts.
    let local = record.cpu_local_memory_access.len() + counter.total_precompile_local_mem_events;
    [
        ("Cpu", counter.num_cpu_events),
        ("DivRem", counter.num_divrem_events.div_ceil(DIVREM_DATAPAR)),
        ("Add", counter.num_add_events.div_ceil(ADD_DATAPAR)),
        ("Sub", counter.num_sub_events.div_ceil(SUB_DATAPAR)),
        ("Addw", counter.num_addw_events.div_ceil(ADD_DATAPAR)),
        ("Subw", counter.num_subw_events.div_ceil(SUB_DATAPAR)),
        (
            "Bitwise",
            counter.num_bitwise_events.div_ceil(BITWISE_DATAPAR),
        ),
        ("Mul", counter.num_mul_events.div_ceil(MUL_DATAPAR)),
        (
            "ShiftRight",
            counter.num_shift_right_events.div_ceil(SR_DATAPAR),
        ),
        (
            "ShiftLeft",
            counter.num_shift_left_events.div_ceil(SLL_DATAPAR),
        ),
        ("LessThan", counter.num_lt_events.div_ceil(LT_DATAPAR)),
        ("MemoryLocal", local.div_ceil(LOCAL_MEMORY_DATAPAR)),
        (
            "MemoryReadWrite",
            counter.num_memory_read_writes.div_ceil(MEMORY_RW_DATAPAR),
        ),
        ("MemoryUnaligned", counter.num_memory_unaligned),
        ("Global", counter.num_global_lookup_events),
        ("SyscallRiscv", counter.num_syscall_events),
        ("Ecall", ecalls),
    ]
    .into_iter()
    .map(|(name, rows)| (name.to_string(), rows))
    .collect()
}

/// The shape a CPU-chunk record proves under: the first [`MLE_CORE_LADDER`] entry that dominates
/// its natural heights componentwise, else the catch-all.
///
/// Returns `None` when even the catch-all does not fit, which callers turn into a panic -- the
/// production config carries the catch-all, so a miss can only mean the chunk is genuinely out
/// of bounds, and a silent fallback would hand the prover a shape its trace overflows.
pub fn select_core_class(natural: &BTreeMap<String, usize>) -> Option<Vec<(String, usize)>> {
    select_core_rung(natural).map(|(_, shape)| shape)
}

/// [`select_core_class`] plus WHICH rung was taken: a ladder row index, or `MLE_CORE_LADDER.len()`
/// for the catch-all. The rung is what a run's cost has to be attributed to -- a chunk on the
/// last rungs pays several times what one on a class does -- so `select_riscv_shape` logs it.
pub fn select_core_rung(
    natural: &BTreeMap<String, usize>,
) -> Option<(usize, Vec<(String, usize)>)> {
    // `MLE_FORCE_CATCH_ALL=1` skips the ladder. It is the switch that takes the ladder out of
    // the path if one of its classes ever turns out to be wrong, and it is what lets a gate
    // prove the catch-all: with the ladder in place no ordinary workload reaches it.
    let force_catch_all = std::env::var("MLE_FORCE_CATCH_ALL").is_ok_and(|v| v == "1");
    let dominates = |class: &[(&str, usize)]| {
        natural.iter().all(|(name, rows)| {
            class
                .iter()
                .find(|(n, _)| n == name)
                .is_some_and(|(_, log)| *rows <= 1usize << *log)
        })
    };
    if !force_catch_all {
        // A row's `MemoryUnaligned` entry is the most it holds, so `dominates` finds the first
        // row that holds the chunk; the chunk then takes that row at the smallest height that
        // holds its misaligned accesses, which is no costlier than any later row.
        let unaligned = natural.get("MemoryUnaligned").copied().unwrap_or(0);
        for (i, class) in MLE_CORE_LADDER.iter().enumerate() {
            if dominates(class) {
                return Some((i, core_rung_shape(class, unaligned_log_height(unaligned))));
            }
        }
    }
    let catch_all: Vec<(String, usize)> = MLE_CORE_CANONICAL_PRESENCE
        .iter()
        .map(|n| (n.to_string(), bucket_log_height(n, true)))
        .collect();
    let refs: Vec<(&str, usize)> = catch_all.iter().map(|(n, h)| (n.as_str(), *h)).collect();
    dominates(&refs).then_some((MLE_CORE_LADDER.len(), catch_all))
}

/// The smallest of [`MLE_MEMORY_UNALIGNED_LOG_HEIGHTS`] that holds `rows` misaligned accesses, or
/// the largest when none does (the caller's row then does not hold the chunk either).
pub fn unaligned_log_height(rows: usize) -> usize {
    MLE_MEMORY_UNALIGNED_LOG_HEIGHTS
        .iter()
        .copied()
        .find(|log| rows <= 1 << log)
        .unwrap_or(MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT)
}

/// `class` with `MemoryUnaligned` at 2^`unaligned`.
fn core_rung_shape(class: &[(&str, usize)], unaligned: usize) -> Vec<(String, usize)> {
    class
        .iter()
        .map(|(n, h)| {
            let h = if *n == "MemoryUnaligned" {
                unaligned
            } else {
                *h
            };
            (n.to_string(), h)
        })
        .collect()
}

/// A core shape a ladder row proves under: `(row, MemoryUnaligned log height, shape)`.
pub type CoreRung = (usize, usize, Vec<(String, usize)>);

/// Every [`CoreRung`]: each row once per height of [`MLE_MEMORY_UNALIGNED_LOG_HEIGHTS`] up to its
/// own entry, in ladder order and smallest height first.
pub fn core_rungs() -> Vec<CoreRung> {
    MLE_CORE_LADDER
        .iter()
        .enumerate()
        .flat_map(|(i, class)| {
            let most = class
                .iter()
                .find(|(n, _)| *n == "MemoryUnaligned")
                .map(|(_, h)| *h)
                .expect("every ladder row names MemoryUnaligned");
            MLE_MEMORY_UNALIGNED_LOG_HEIGHTS
                .iter()
                .copied()
                .filter(move |log| *log <= most)
                .map(move |log| (i, log, core_rung_shape(class, log)))
        })
        .collect()
}

/// Whether a core shape is the catch-all row: every air at its `MLE_RISCV_MAIN_LOG_HEIGHTS`
/// height. Its GKR leaf buffer is 64 GiB, so the provers refuse a chunk that selects it (see
/// `riscv::CatchAllShape`).
pub fn is_core_catch_all(shape: &[(String, usize)]) -> bool {
    shape
        .iter()
        .all(|(name, log)| *log == bucket_log_height(name, true))
}

/// The shape a record proves under, given the airs it declares present.
///
/// A CPU chunk takes a [`MLE_CORE_LADDER`] class, so the core family pads to one of a handful of
/// whole height vectors. The other two families take their natural heights: their enumerations
/// carry every integer height in range, so there is nothing to round up to beyond the power of
/// two a trace pads to anyway. Byte, Program and Global are pinned machine-wide in all three:
/// Global takes [`MLE_GLOBAL_LOG_HEIGHT`] whatever its event count.
///
/// Panics when nothing fits. The production config carries the catch-all, so a miss can only
/// mean the chunk is genuinely out of bounds, and padding it into a shape it overflows would
/// fail later and less legibly. Panics, too, when a deferred chunk's heights are not a whitelist
/// shape, for the same reason.
pub fn select_riscv_shape(
    present: &[String],
    natural: &BTreeMap<String, usize>,
    is_cpu_chunk: bool,
) -> Vec<(String, usize)> {
    if is_cpu_chunk {
        let (rung, class) = select_core_rung(natural).unwrap_or_else(|| {
            panic!(
                "no MLE core shape holds this chunk, the catch-all included: {}",
                over_the_catch_all(natural, true)
            )
        });
        // One line per chunk, so a run's cost can be attributed: an envelope row costs more than
        // the classes around it and the catch-all several times a class.
        let name = match rung {
            r if r == MLE_CORE_LADDER.len() => "catch-all".to_string(),
            r if r >= MLE_CORE_FITTED_ROWS => format!("added{r}"),
            r if MLE_CORE_ENVELOPE_ROWS.contains(&r) => format!("envelope{r}"),
            r => format!("class{r}"),
        };
        let unaligned = class
            .iter()
            .find(|(n, _)| n == "MemoryUnaligned")
            .map_or(0, |(_, h)| *h);
        tracing::info!(
            target: "mle_shape",
            "core chunk takes rung {name}, MemoryUnaligned at 2^{unaligned}"
        );
        debug_assert_eq!(
            class.len(),
            present.len(),
            "the class is not the present set"
        );
        return class;
    }
    tracing::info!(
        target: "mle_shape",
        "deferred chunk takes its natural heights ({} airs)",
        present.len()
    );
    let mut shape: Vec<(String, usize)> = present
        .iter()
        .map(|name| {
            if name == "Byte" || name == "Program" {
                return (name.clone(), bucket_log_height(name, false));
            }
            let rows = natural.get(name).copied().unwrap_or_else(|| {
                panic!(
                    "air `{name}` is present but has no natural height; mle_natural_heights \
                        and the machine's chip set have drifted apart"
                )
            });
            let log = rows
                .max(1)
                .next_power_of_two()
                .ilog2()
                .max(MLE_MIN_LOG_HEIGHT as u32) as usize;
            let cap = bucket_log_height(name, false);
            assert!(
                log <= cap,
                "no MLE shape holds this chunk: {name} needs 2^{log} ({rows} rows) but its \
                 catch-all is 2^{cap}"
            );
            if name == "Global" {
                return (name.clone(), MLE_GLOBAL_LOG_HEIGHT);
            }
            (name.clone(), log)
        })
        .collect();
    pad_blake2b_calls_under_rounds(&mut shape);
    assert_whitelist_shape(&shape, natural);
    shape
}

/// Pad a BLAKE2b chunk's control chip and syscall table to [`blake2b_call_log_height`] of its
/// round chip, the one call height the enumeration lists per round height. The calls fit under
/// it (each runs a round or more, and the split caps them), so this only ever pads.
fn pad_blake2b_calls_under_rounds(shape: &mut [(String, usize)]) {
    let Some(rounds) = shape
        .iter()
        .find(|(name, _)| name == "Blake2bRound")
        .map(|(_, log)| *log)
    else {
        return;
    };
    let calls = blake2b_call_log_height(rounds);
    for (name, log) in shape.iter_mut() {
        if name == "Blake2bControl" || name == "SyscallPrecompile" {
            assert!(
                *log <= calls,
                "a BLAKE2b chunk's {name} needs 2^{log}, above the 2^{calls} its 2^{rounds} rounds \
                 allow: a call ran no rounds, or the split let the calls past their cap"
            );
            *log = calls;
        }
    }
}

/// Every riscv shape the whitelist admits, each sorted by chip name, built once per process.
fn whitelist_shapes() -> &'static std::collections::HashSet<Vec<(String, usize)>> {
    static SHAPES: std::sync::OnceLock<std::collections::HashSet<Vec<(String, usize)>>> =
        std::sync::OnceLock::new();
    SHAPES.get_or_init(|| {
        mle_riscv_shapes()
            .into_iter()
            .map(|(_, mut shape)| {
                shape.sort();
                shape
            })
            .collect()
    })
}

/// A deferred chunk proves at its own heights, so nothing before this point makes them a
/// whitelist shape. Checked here, where the heights are at hand: a chunk that fails it would
/// otherwise only surface at its parent combine, as a child key missing from the whitelist.
fn assert_whitelist_shape(shape: &[(String, usize)], natural: &BTreeMap<String, usize>) {
    let mut sorted = shape.to_vec();
    sorted.sort();
    assert!(
        whitelist_shapes().contains(&sorted),
        "a deferred chunk's heights are not a whitelist shape, so its convert key would not be in \
         the whitelist: {} (natural rows: {})",
        shape
            .iter()
            .map(|(name, log)| format!("{name}=2^{log}"))
            .collect::<Vec<_>>()
            .join(" "),
        natural
            .iter()
            .map(|(name, rows)| format!("{name}={rows}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
}

/// Which airs of a record stand above the catch-all, for a panic message.
fn over_the_catch_all(natural: &BTreeMap<String, usize>, is_cpu_chunk: bool) -> String {
    natural
        .iter()
        .filter_map(|(name, rows)| {
            let log = rows.max(&1).next_power_of_two().ilog2() as usize;
            let cap = bucket_log_height(name, is_cpu_chunk);
            (log > cap).then(|| format!("{name} needs 2^{log} ({rows} rows) over 2^{cap}"))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The precompile chip names, in machine order, built once: `get_all_precompile_chips`
/// constructs every precompile `MetaChip`, and a keccak chip's construction alone runs its
/// constraints symbolically -- about a second per call, which a per-chunk walk would pay on
/// EVERY deferred chunk (the riscv preparer lane at 1.2 s per chunk, the provers idling behind
/// it).
fn precompile_kinds() -> &'static [String] {
    static KINDS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    KINDS.get_or_init(|| {
        crate::instances::chiptype::riscv_chiptype::RiscvChipType::<Kb>::get_all_precompile_chips()
            .into_iter()
            .map(|(kind, _)| kind)
            .collect()
    })
}

/// Return `program` with its preprocessed shape pinned to the MLE bucket (the program table at
/// [`MLE_RISCV_PROGRAM_LOG_HEIGHT`]). Idempotent; panics if a DIFFERENT preprocessed shape is
/// already set (the FRI shape system and the MLE bucket must not be mixed).
pub fn with_mle_preprocessed_shape(program: Arc<Program>) -> Arc<Program> {
    // The table is pinned machine-wide, so a guest it cannot hold is a config change, not a
    // per-chunk one: say which constant to raise (and that raising it rebuilds the whitelist).
    assert!(
        program.instructions.len() <= 1 << MLE_RISCV_PROGRAM_LOG_HEIGHT,
        "the guest has {} instructions, above the 2^{} program table: raise \
         MLE_RISCV_PROGRAM_LOG_HEIGHT and rebuild the vk whitelist",
        program.instructions.len(),
        MLE_RISCV_PROGRAM_LOG_HEIGHT
    );
    let bucket = RiscvPadShape {
        inner: [("Program".to_string(), MLE_RISCV_PROGRAM_LOG_HEIGHT)]
            .into_iter()
            .collect(),
    };
    match &program.preprocessed_shape {
        Some(existing) if *existing == bucket => program,
        Some(other) => panic!(
            "program already carries a non-MLE preprocessed shape: {:?}",
            other.inner
        ),
        None => {
            let mut p = (*program).clone();
            p.preprocessed_shape = Some(bucket);
            Arc::new(p)
        }
    }
}

/// Node role in the recursion tree — the tree grammar is fixed (converts verify bucketed
/// RISC-V proofs; combines verify convert-/combine-tier proofs), so shapes are selected by
/// role rather than closest-fit matching: role selection is data-independent, which pins the
/// child-shape base to exactly {C0, C1, C2, G, B} and keeps the whitelist's shape product at 50
/// combine entries (the ordered pairs at both completeness flags). (FRI's closest-fit over a
/// multi-shape allowed set is data-dependent, so its
/// whole cartesian product must be preregistered — see `get_all_shape_combinations`.)
/// The root is NOT a tier: it is just the last combine round with `is_complete = true`,
/// exactly as in the FRI path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecursionTier {
    /// A convert node, padded to this row of [`MLE_RECURSION_CONVERT_LADDER`]. The global
    /// LogUp's image node takes row 0.
    Convert(usize),
    /// A group node of the global LogUp, whatever the number of tables in its group
    /// ([`MLE_RECURSION_GROUP_NODE_LOG_HEIGHTS`]).
    GroupNode,
    Combine,
    /// The embed node, which re-proves the compress proof under the outer BN254-hashed config.
    /// Its table is the program's natural heights in whitelist mode, over the compress
    /// proof's layout, measured by the tier probe. It is not in `mle_shape_config_digest`: the
    /// embed key is no whitelist leaf, so the table moves only the embed key.
    Embed,
    /// The compress node, which re-proves the complete root under the inner config at the
    /// compress preset (the final compression layer). Its table is the program's natural heights
    /// in whitelist mode, measured by the tier probe; they decide the
    /// whitelist-mode proof size.
    Compress,
}

/// Convert-tier log2 heights, as a ladder: a convert program takes the FIRST row that holds its
/// natural heights (`select_convert_row`), and the last row holds every shape the whitelist
/// admits, so selection always terminates. `convert_ladder_rows_close_under_the_last` holds the
/// rows under the last one; that the last row holds every whitelist shape is what the builder
/// and the tier probe assert (`check_recursion_tier` over the whole enumeration). Rows sit
/// cheapest first by stacked width W = sum(w_main * 2^h) / 2^21, the quantity the convert time
/// follows (~154 + 1.45 W ms on one card, a KoalaBear⁴ calibration).
///
/// One tier for every child would be the componentwise maximum over the whole enumeration,
/// W = 68, set by the last core rows and the catch-all (Poseidon2Packed, ExtDotProduct,
/// MemoryVar), by keccak (MemoryConst) and by the BLS12-381 G2 precompiles (ExtAlu, MleOpen),
/// while the children the corpus actually produces need W = 14..29. With rows, each child pads to
/// the nearest row above it and the combine machine learns one child layout per row
/// (`preregister_standard_shapes`).
///
/// Of the 4,737 whitelist shapes, row 0 (W 21) holds 4,155: 90 core shapes (classes 0 to 13 at
/// every `MemoryUnaligned` height, classes 14 to 20 at the lower ones), the 399 memory shapes and
/// every precompile shape but keccak's, the two BLS12-381 G2 kinds' and 47 of
/// Bls12381DoubleAssign's; row 1 (W 35) 381: 55 core shapes (classes 14 to 20 at the higher
/// `MemoryUnaligned` heights, 21 to 27 and core row 34 at all), the 279 keccak shapes and those
/// 47; row 2 (W 68) the 201 left, core classes 28 to 32, core row 33, the catch-all and the 171 G2
/// shapes, which set its ExtAlu and MleOpen heights. A class moves up a row at a higher
/// `MemoryUnaligned` height on the convert program's `Poseidon2Packed` table, which the taller
/// trace lengthens past row 0's 2^17 (class 19 from 2^17 to 2^18 at 2^16 misaligned rows). Row 2
/// sits over row 1 on every chip (`convert_ladder_rows_close_under_the_last`). Of the 4,713
/// chunks of the 80-block p99 corpus (built without misaligned accesses, so all at 2^10) 4,256
/// take row 0, 457 row 1 and none row 2, and the padding costs 2.3% over the natural heights. The
/// global LogUp's image node pads to row 0 at every tier of its table.
///
/// Fitted (2026-11-13) over that corpus, with the natural riscv heights of the same day under
/// the 33-row core ladder and the convert heights `examples/mle_tier_probe.rs` measured over the
/// whole enumeration. The fitting tools and the runs' records are not part of this repository
/// (`docs/tier-tables.md`). The probe walks every whitelist shape and reports which row it
/// takes and the slack it leaves.
///
/// Converts have no fixpoint concern: their children are RISC-V proofs, not recursion proofs.
pub const MLE_RECURSION_CONVERT_LADDER: &[&[(&str, usize)]] = &[
    // row 0: W = 21
    &[
        ("ExtAlu", 17),
        ("ExtDotProduct", 17),
        ("Poseidon2Packed", 17),
        ("MemoryVar", 16),
        ("HornerEval", 15),
        ("MemoryConst", 13),
        ("BaseAlu", 14),
        ("AssertZeroExt", 14),
        ("UnpackBlock", 15),
        ("ExpBitsLen", 15),
        ("MleOpen", 12),
        ("DigestSelect", 15),
        ("BinaryFoldStep", 14),
        ("PackBlock", 13),
        ("GkrSumcheckRound", 9),
        ("FracFold", 5),
        ("LagrangeEvalD2", 6),
        ("Select", 4),
        ("Poseidon2", 4),
        ("PublicValues", 4),
        ("UnivariateFold", 4),
    ],
    // row 1: W = 35
    &[
        ("ExtAlu", 18),
        ("ExtDotProduct", 17),
        ("Poseidon2Packed", 18),
        ("MemoryVar", 16),
        ("HornerEval", 15),
        ("MemoryConst", 14),
        ("BaseAlu", 14),
        ("AssertZeroExt", 14),
        ("UnpackBlock", 16),
        ("ExpBitsLen", 15),
        ("MleOpen", 12),
        ("DigestSelect", 15),
        ("BinaryFoldStep", 14),
        ("PackBlock", 14),
        ("GkrSumcheckRound", 9),
        ("FracFold", 5),
        ("LagrangeEvalD2", 6),
        ("Select", 4),
        ("Poseidon2", 4),
        ("PublicValues", 4),
        ("UnivariateFold", 4),
    ],
    // row 2: W = 68
    &[
        ("ExtAlu", 19),
        ("ExtDotProduct", 18),
        ("Poseidon2Packed", 19),
        ("MemoryVar", 18),
        ("HornerEval", 15),
        ("MemoryConst", 14),
        ("BaseAlu", 14),
        ("AssertZeroExt", 14),
        ("UnpackBlock", 16),
        ("ExpBitsLen", 15),
        ("MleOpen", 13),
        ("DigestSelect", 15),
        ("BinaryFoldStep", 14),
        ("PackBlock", 14),
        ("GkrSumcheckRound", 9),
        ("FracFold", 5),
        ("LagrangeEvalD2", 6),
        ("Select", 4),
        ("Poseidon2", 4),
        ("PublicValues", 4),
        ("UnivariateFold", 4),
    ],
];

/// The row every group node of the global LogUp pads to: the per-chip maximum of the natural
/// heights of the group-node programs over 1 to `MAX_GROUP_LEN` tables, measured by
/// `examples/mle_tier_probe.rs`, no slack. A row of its own, not a ladder row: it is above the
/// last convert row on the chips that follow the number of tables a group proof opens
/// (DigestSelect, UnpackBlock, AssertZeroExt, PackBlock) and at or below it on the rest, so
/// neither holds the other. To a combine node a group node is one more child kind, G.
pub const MLE_RECURSION_GROUP_NODE_LOG_HEIGHTS: &[(&str, usize)] = &[
    ("ExtAlu", 15),
    ("HornerEval", 15),
    ("Poseidon2Packed", 18),
    ("MemoryVar", 17),
    ("ExtDotProduct", 17),
    ("ExpBitsLen", 15),
    ("BaseAlu", 14),
    ("AssertZeroExt", 15),
    ("BinaryFoldStep", 14),
    ("UnpackBlock", 17),
    ("MemoryConst", 10),
    ("DigestSelect", 17),
    ("PackBlock", 15),
    ("MleOpen", 8),
    ("GkrSumcheckRound", 9),
    ("FracFold", 5),
    ("LagrangeEvalD2", 6),
    ("Select", 4),
    ("Poseidon2", 4),
    ("PublicValues", 4),
    ("UnivariateFold", 4),
];

/// Combine-tier log2 heights, shared by EVERY combine node including the root (the last,
/// `is_complete = true` round): the per-chip maximum over the 50 node shapes
/// `preregister_standard_shapes` builds (the ordered pairs over {C0, C1, C2, G, B} at both
/// completeness flags), measured by `examples/mle_tier_probe.rs` over the convert rows and the
/// group nodes' row above (2026-11-13), no slack. The peaks: ExtDotProduct and MemoryVar at
/// [C0,C2], UnpackBlock and GkrSumcheckRound at [C0,C1], the rest at [C0,C0]; no pair with a G
/// child sets one. The deferred node pads to this row too and sits under it on every chip.
/// Tier-padded children and the membership circuit are what the measurement covers; an overflow
/// fails loudly with the chip's row width in the panic.
///
/// The root is a combine node on this table too; a root-specific table would reclaim what the
/// root leaves under it, at the cost of a whitelist REBUILD rather than more whitelist entries
/// (role-based selection keeps the child-shape base at {C0, C1, C2, G, B}; the root is never a
/// child). The row is taken over the complete and the non-complete pairs alike, so the shared
/// table is the conservative choice.
pub const MLE_RECURSION_COMBINE_LOG_HEIGHTS: &[(&str, usize)] = &[
    ("ExtAlu", 17),
    ("HornerEval", 17),
    ("Poseidon2Packed", 17),
    ("MemoryVar", 16),
    ("ExtDotProduct", 16),
    ("ExpBitsLen", 15),
    ("BaseAlu", 14),
    ("AssertZeroExt", 15),
    ("BinaryFoldStep", 14),
    ("UnpackBlock", 16),
    ("MemoryConst", 13),
    ("DigestSelect", 15),
    ("PackBlock", 14),
    ("MleOpen", 12),
    ("GkrSumcheckRound", 10),
    ("FracFold", 6),
    ("LagrangeEvalD2", 6),
    ("Select", 4),
    ("Poseidon2", 4),
    ("PublicValues", 4),
    ("UnivariateFold", 4),
];

/// Embed-tier log2 heights: the natural heights of the embed program in whitelist mode, where its
/// child is the compress proof, padded to the compress row (`compress_proof_layout`), measured by
/// the tier probe (2026-11-02), no slack. Measured after the compress row: a change to
/// that row or to the compress preset means measuring this one again. Not in
/// `mle_shape_config_digest`.
pub const MLE_RECURSION_EMBED_LOG_HEIGHTS: &[(&str, usize)] = &[
    ("ExtAlu", 16),
    ("HornerEval", 13),
    ("Poseidon2Packed", 14),
    ("MemoryVar", 13),
    ("ExtDotProduct", 13),
    ("ExpBitsLen", 13),
    ("BaseAlu", 12),
    ("AssertZeroExt", 12),
    ("BinaryFoldStep", 11),
    ("UnpackBlock", 13),
    ("MemoryConst", 12),
    ("DigestSelect", 12),
    ("PackBlock", 12),
    ("MleOpen", 11),
    ("GkrSumcheckRound", 8),
    ("FracFold", 5),
    ("LagrangeEvalD2", 5),
    ("Select", 4),
    ("Poseidon2", 4),
    ("PublicValues", 4),
    ("UnivariateFold", 4),
];

/// Compress-tier log2 heights: the natural heights of the compress program in whitelist mode, where
/// the root it re-proves has the one combine-tier (B) layout, measured by the tier probe
/// (2026-10-27), no slack. The proof size in whitelist mode follows this row (one notch of slack on
/// Poseidon2Packed alone adds ~11 stacked columns, ~45 KiB), and the whitelist-mode proof must have
/// the largest dev-mode shape. The per-chip maximum of the dev-mode natural heights
/// (`recursion_heights[compress]` of a `--step compress` run on fib-10 and reth 18884864 /
/// 24600825, when the compress layer was introduced) is this row (PackBlock sits one notch under it
/// on the two reth blocks), and the whitelist-mode proof measured on the same three inputs has the
/// dev-mode figures: every chip at its row (slack 0), stacked width 20 + 5 = 25, 299,231 bytes,
/// 128.05 bits.
pub const MLE_RECURSION_COMPRESS_LOG_HEIGHTS: &[(&str, usize)] = &[
    ("ExtAlu", 16),
    ("HornerEval", 16),
    ("Poseidon2Packed", 16),
    ("MemoryVar", 14),
    ("ExtDotProduct", 14),
    ("ExpBitsLen", 14),
    ("BaseAlu", 13),
    ("AssertZeroExt", 14),
    ("BinaryFoldStep", 13),
    ("UnpackBlock", 14),
    ("MemoryConst", 12),
    ("DigestSelect", 14),
    ("PackBlock", 13),
    ("MleOpen", 11),
    ("GkrSumcheckRound", 8),
    ("FracFold", 5),
    ("LagrangeEvalD2", 5),
    ("Select", 4),
    ("Poseidon2", 4),
    ("PublicValues", 4),
    ("UnivariateFold", 4),
];

/// The pad shape for a recursion tree role (see [`RecursionTier`]).
pub fn mle_recursion_pad_shape_for(
    tier: RecursionTier,
) -> crate::instances::compiler::shapes::recursion_shape::RecursionPadShape {
    let table = match tier {
        RecursionTier::Convert(row) => MLE_RECURSION_CONVERT_LADDER[row],
        RecursionTier::GroupNode => MLE_RECURSION_GROUP_NODE_LOG_HEIGHTS,
        RecursionTier::Combine => MLE_RECURSION_COMBINE_LOG_HEIGHTS,
        RecursionTier::Embed => MLE_RECURSION_EMBED_LOG_HEIGHTS,
        RecursionTier::Compress => MLE_RECURSION_COMPRESS_LOG_HEIGHTS,
    };
    crate::instances::compiler::shapes::recursion_shape::RecursionPadShape {
        inner: table.iter().map(|(n, log)| (n.to_string(), *log)).collect(),
    }
}

/// [`mle_recursion_pad_shape_for`] raised wherever `natural` (the program's
/// [`crate::mle::machine::recursion::recursion_natural_rows`]) is taller than the table: the
/// shape a keygen can take on a table the circuits have outgrown (`padded_row_count` refuses a
/// declared height below the real one). For the tier probe's report-only mode only; the prover
/// pads to the table and nothing else, and `check_recursion_tier` refuses the overflow there.
/// A chip the table lacks is left as it is: the probe runs `recursion_tier_fit` first, which
/// panics on it.
pub fn mle_recursion_pad_shape_holding(
    tier: RecursionTier,
    natural: &[(String, usize)],
) -> crate::instances::compiler::shapes::recursion_shape::RecursionPadShape {
    let mut pad = mle_recursion_pad_shape_for(tier);
    for (name, rows) in natural {
        let log = rows.next_power_of_two().trailing_zeros() as usize;
        if let Some(tier_log) = pad.inner.get_mut(name) {
            if log > *tier_log {
                *tier_log = log;
            }
        }
    }
    pad
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every air the RISC-V machine can activate must have a catch-all height, in both chunk
    /// kinds. `bucket_log_height` panics on a chip it has no entry for, and that panic only
    /// surfaces once something proves — which is too late to notice a table edit dropped a chip.
    #[test]
    fn every_air_has_a_catch_all_height() {
        let mut seen = 0;
        while let Some(name) = crate::mle::machine::riscv::air_name(seen) {
            seen += 1;
            for is_cpu_chunk in [true, false] {
                let log = bucket_log_height(name, is_cpu_chunk);
                assert!(
                    log <= crate::mle::machine::riscv::DEFAULT_LOG_STACKED_HEIGHT,
                    "{name} is bucketed to 2^{log}, above the stacked height"
                );
            }
        }
        assert_eq!(seen, 55, "the machine's air list changed size");
    }

    /// The three kinds the split sizes by the hardware-tier threshold rather than by cells: their
    /// catch-all must hold a full block. Were one of them to gain a `tail_rows_and_width` entry,
    /// its block would be cells-derived and could outgrow the height below.
    #[test]
    fn tier_threshold_kinds_fit_a_full_block() {
        use crate::{
            emulator::riscv::{
                record::{get_prover_hardware_config, tail_rows_and_width},
                syscalls::SyscallCode,
            },
            instances::compiler::shapes::riscv_shape::precompile_rows_per_event,
        };
        for (kind, code) in [
            ("Poseidon2Permute", SyscallCode::POSEIDON2_PERMUTE),
            ("EdAddAssign", SyscallCode::ED_ADD),
            ("EdDecompress", SyscallCode::ED_DECOMPRESS),
        ] {
            assert!(
                tail_rows_and_width(code).is_none(),
                "{kind} is now cells-sized; its catch-all has to be re-derived"
            );
            let rows =
                get_prover_hardware_config().get_threshold(code) * precompile_rows_per_event(kind);
            assert!(
                rows <= 1 << bucket_log_height(kind, false),
                "{kind}: a full block is {rows} rows, above its catch-all 2^{}",
                bucket_log_height(kind, false)
            );
        }
    }

    /// The sliced Keccak: a full split block (`EmulationRecord::split`, 38836 permutations) fits its
    /// catch-all, the 2^4 and 2^9 heights its layout skips admit no event count, every other height up to
    /// the catch-all admits a window, and the table entries are the tables' real height.
    #[test]
    fn sliced_keccak_shapes_match_the_layout() {
        use crate::{
            chips::precompiles::keccak256::sliced::{sliced_height, TABLE_ROWS},
            instances::compiler::shapes::riscv_shape::precompile_tables,
        };
        let cap = bucket_log_height("KeccakPermute", false);
        assert_eq!(sliced_height(2 * ((1 << 19) / 27)), 1 << cap);
        assert!(sliced_height(2 * ((1 << 19) / 27) + 1) > 1 << cap);
        // 2^4 is under one 27-row slot; 2^9 would end on a clk-25 row and doubles.
        assert_eq!(kind_event_window("KeccakPermute", 4), None);
        assert_eq!(kind_event_window("KeccakPermute", 9), None);
        for k in (MLE_MIN_LOG_HEIGHT..=cap).filter(|k| *k != 4 && *k != 9) {
            let (lo, hi) = kind_event_window("KeccakPermute", k)
                .unwrap_or_else(|| panic!("no event count lands on 2^{k}"));
            for n in [lo, hi] {
                assert_eq!(sliced_height(n), 1 << k, "n = {n} at 2^{k}");
            }
            assert!(lo == 1 || sliced_height(lo - 1) < 1 << k);
            assert!(sliced_height(hi + 1) > 1 << k);
        }
        for (table, log) in precompile_tables("KeccakPermute") {
            assert_eq!(1 << log, TABLE_ROWS, "{table}");
            assert_eq!(bucket_log_height(table, false), *log, "{table}");
        }
        // The linear kinds keep the closed form the enumeration had before the window search.
        for (kind, rpe, k) in [("ShaCompress", 80usize, 12usize), ("Uint256MulMod", 1, 4)] {
            let lo = if k == MLE_MIN_LOG_HEIGHT {
                1
            } else {
                ((1 << (k - 1)) + 1usize).div_ceil(rpe)
            };
            assert_eq!(
                kind_event_window(kind, k),
                Some((lo, (1 << k) / rpe)),
                "{kind} 2^{k}"
            );
        }
        assert_eq!(kind_event_window("ShaCompress", 6), None);
    }

    /// The program table's preprocessed height and its main multiplicity trace must agree.
    #[test]
    fn program_main_matches_its_preprocessed_height() {
        assert_eq!(
            bucket_log_height("Program", true),
            MLE_RISCV_PROGRAM_LOG_HEIGHT
        );
    }

    /// Every ladder class must sit under the catch-all componentwise, or the catch-all stops
    /// being the last rung, and must carry exactly the core family -- a class that named a chip
    /// the family does not have, or missed one, would not be a whole height vector.
    #[test]
    fn core_ladder_classes_sit_under_the_catch_all() {
        assert!(!MLE_CORE_LADDER.is_empty(), "the core ladder is empty");
        for (i, class) in MLE_CORE_LADDER.iter().enumerate() {
            let names: Vec<&str> = class.iter().map(|(n, _)| *n).collect();
            for member in MLE_CORE_CANONICAL_PRESENCE {
                assert!(names.contains(member), "class {i} is missing {member}");
            }
            assert_eq!(
                names.len(),
                MLE_CORE_CANONICAL_PRESENCE.len(),
                "class {i} carries chips outside the core family"
            );
            for (name, log) in class.iter() {
                let cap = bucket_log_height(name, true);
                assert!(
                    *log <= cap,
                    "class {i}: {name} at 2^{log} exceeds the catch-all 2^{cap}"
                );
            }
        }
    }

    /// Nothing the precompile generator emits may exceed the family catch-all: the ladder is
    /// only usable if the catch-all is still the last rung.
    #[test]
    fn precompile_shapes_stay_under_the_catch_all() {
        let shapes = mle_precompile_shapes();
        assert!(
            !shapes.is_empty(),
            "the precompile family generated nothing"
        );
        for s in &shapes {
            let check = |name: &str, h: usize| {
                let cap = bucket_log_height(name, false);
                assert!(h <= cap, "{} at 2^{h} exceeds its catch-all 2^{cap}", name);
            };
            check(&s.kind, s.kind_log_height);
            check("SyscallPrecompile", s.syscall_precompile);
            check("MemoryLocal", s.memory_local);
            if let Some((name, h)) = &s.control {
                check(name, *h);
            }
        }
    }

    /// The generator must keep the relation the catch-all is built on: a control sibling emits
    /// one row per parent event, exactly as the syscall chip does.
    #[test]
    fn precompile_shapes_keep_the_structural_relations() {
        for s in mle_precompile_shapes() {
            if let Some((name, h)) = &s.control {
                assert_eq!(
                    *h, s.syscall_precompile,
                    "{} 2^{}: {name} 2^{h} and SyscallPrecompile 2^{} disagree, though both are \
                     one row per event",
                    s.kind, s.kind_log_height, s.syscall_precompile
                );
            }
        }
    }

    /// A deferred chunk with these natural rows, as `select_riscv_shape` sees it: the airs
    /// `natural` names, plus Byte and Program.
    fn select_deferred(natural: &[(&str, usize)]) -> BTreeMap<String, usize> {
        let natural: BTreeMap<String, usize> = natural
            .iter()
            .map(|(name, rows)| (name.to_string(), *rows))
            .collect();
        let present: Vec<String> = ["Byte", "Program"]
            .into_iter()
            .map(str::to_string)
            .chain(natural.keys().cloned())
            .collect();
        select_riscv_shape(&present, &natural, false)
            .into_iter()
            .collect()
    }

    /// Bottom of the range, each power of two up to `max`, and one either side of each.
    fn edges(max: usize) -> std::collections::BTreeSet<usize> {
        (0..usize::BITS)
            .map(|k| 1usize << k)
            .take_while(|p| *p <= max)
            .flat_map(|p| [p - 1, p, p + 1])
            .chain([1, 2, 3, max])
            .filter(|v| (1..=max).contains(v))
            .collect()
    }

    /// Every precompile chunk the airs can raise selects a whitelist shape. The natural rows are
    /// what the generators read: `n * rows_per_event` on the kind, `n` on its syscall and control
    /// siblings, `ceil(local / LOCAL_MEMORY_DATAPAR)` on MemoryLocal and `2 * local + n` on
    /// Global, for `local` up to what `n` events can touch and the Global table can hold. The
    /// sweep walks every height boundary and puts the global event count on each power of two
    /// it reaches, the full table among them.
    #[test]
    fn every_precompile_chunk_selects_a_whitelist_shape() {
        use crate::{
            instances::{
                chiptype::riscv_chiptype::RiscvChipType,
                compiler::shapes::riscv_shape::{
                    precompile_kind_rows, precompile_rows_per_event, precompile_tables,
                },
            },
            primitives::consts::LOCAL_MEMORY_DATAPAR,
        };
        let global_rows_cap = 1usize << bucket_log_height("Global", false);
        let local_cap = (1usize << bucket_log_height("MemoryLocal", false)) * LOCAL_MEMORY_DATAPAR;
        let mut chunks = 0usize;
        for (kind, _) in RiscvChipType::<Kb>::get_all_precompile_chips()
            .into_iter()
            .filter(|(kind, _)| crate::mle::machine::riscv::air_id_for(kind).is_some())
            // Its rounds and calls are independent; `every_blake2b_chunk_selects_a_whitelist_shape`.
            .filter(|(kind, _)| kind != "Blake2bRound")
        {
            let rows_per_event = precompile_rows_per_event(&kind);
            let control = precompile_control_sibling(&kind);
            let mem_per_event = rows_per_event * memory_lookups_per_row(&kind)
                + control.map_or(0, memory_lookups_per_row);
            let n_max = [
                kind_event_window(&kind, bucket_log_height(&kind, false)).map_or(0, |(_, hi)| hi),
                1 << bucket_log_height("SyscallPrecompile", false),
                control.map_or(usize::MAX, |c| 1 << bucket_log_height(c, false)),
            ]
            .into_iter()
            .min()
            .unwrap();
            // Where the syscall's height turns over, and where the kind's does.
            let mut ns = edges(n_max);
            ns.extend(
                (MLE_MIN_LOG_HEIGHT..=bucket_log_height(&kind, false))
                    .filter_map(|k| kind_event_window(&kind, k))
                    .flat_map(|(lo, hi)| [lo, hi, hi + 1])
                    .filter(|n| (1..=n_max).contains(n)),
            );
            for n in ns {
                let local_max = (n * mem_per_event)
                    .min(local_cap)
                    .min((global_rows_cap - n) / 2);
                // Where MemoryLocal's height turns over.
                let mut locals = edges(local_max);
                locals.extend(
                    edges(local_max.div_ceil(LOCAL_MEMORY_DATAPAR))
                        .into_iter()
                        .map(|rows| rows * LOCAL_MEMORY_DATAPAR)
                        .flat_map(|l| [l, l + 1]),
                );
                // The global event count `2 * local + n` on each power of two and either side.
                locals.extend(
                    (0..usize::BITS)
                        .map(|k| 1usize << k)
                        .flat_map(|p| [p - 1, p, p + 1])
                        .filter(|e| *e > n && (e - n) % 2 == 0)
                        .map(|e| (e - n) / 2),
                );
                for local in locals.into_iter().filter(|l| (1..=local_max).contains(l)) {
                    let events = 2 * local + n;
                    let mut natural = vec![
                        (kind.as_str(), precompile_kind_rows(&kind, n)),
                        ("SyscallPrecompile", n),
                        ("MemoryLocal", local.div_ceil(LOCAL_MEMORY_DATAPAR)),
                        ("Global", events),
                    ];
                    natural.extend(control.map(|c| (c, n)));
                    natural.extend(precompile_tables(&kind).iter().map(|(t, h)| (*t, 1 << h)));
                    let shape = select_deferred(&natural);
                    assert_eq!(shape["Global"], MLE_GLOBAL_LOG_HEIGHT);
                    chunks += 1;
                }
            }
        }
        assert!(chunks > 0, "the sweep selected no chunk");
    }

    /// Every BLAKE2b chunk the split can form selects a whitelist shape: `rounds` up to the full
    /// block, `calls` from one up to the fewer of the rounds and the call cap, `local` up to what
    /// the calls can touch and the Global table can hold, each walked over its height boundaries,
    /// and the global event count `2 * local + calls` put on each power of two it reaches.
    #[test]
    fn every_blake2b_chunk_selects_a_whitelist_shape() {
        use crate::{
            chips::precompiles::blake2b::{CALLS_PER_BLOCK_LOG, ROUNDS_PER_BLOCK_LOG},
            primitives::consts::LOCAL_MEMORY_DATAPAR,
        };
        let global_rows_cap = 1usize << bucket_log_height("Global", false);
        let local_cap = (1usize << bucket_log_height("MemoryLocal", false)) * LOCAL_MEMORY_DATAPAR;
        let mem_per_call = memory_lookups_per_row("Blake2bControl");
        let mut checked = 0usize;
        for rounds in edges(1 << ROUNDS_PER_BLOCK_LOG) {
            for calls in edges(rounds.min(1 << CALLS_PER_BLOCK_LOG)) {
                let local_max = (calls * mem_per_call)
                    .min(local_cap)
                    .min((global_rows_cap - calls) / 2);
                let mut locals = edges(local_max);
                locals.extend(
                    edges(local_max.div_ceil(LOCAL_MEMORY_DATAPAR))
                        .into_iter()
                        .map(|rows| rows * LOCAL_MEMORY_DATAPAR)
                        .flat_map(|l| [l, l + 1]),
                );
                locals.extend(
                    (0..usize::BITS)
                        .map(|k| 1usize << k)
                        .flat_map(|p| [p - 1, p, p + 1])
                        .filter(|e| *e > calls && (e - calls) % 2 == 0)
                        .map(|e| (e - calls) / 2),
                );
                for local in locals.into_iter().filter(|l| (1..=local_max).contains(l)) {
                    let shape = select_deferred(&[
                        ("Blake2bRound", rounds),
                        ("Blake2bControl", calls),
                        ("SyscallPrecompile", calls),
                        ("MemoryLocal", local.div_ceil(LOCAL_MEMORY_DATAPAR)),
                        ("Global", 2 * local + calls),
                    ]);
                    assert_eq!(shape["Global"], MLE_GLOBAL_LOG_HEIGHT);
                    checked += 1;
                }
            }
        }
        assert!(checked > 0, "the sweep checked nothing");
    }

    /// Every memory chunk under the caps selects a whitelist shape. MemoryInitialize and
    /// MemoryFinalize take a row per event and Global `init + fin`; the sweep puts `init + fin`
    /// on each power of two, the full Global table among them, as well as walking each side's
    /// boundaries.
    #[test]
    fn every_memory_chunk_selects_a_whitelist_shape() {
        let side_cap = 1usize
            << bucket_log_height("MemoryInitialize", false)
                .min(bucket_log_height("MemoryFinalize", false));
        let global_rows_cap = 1usize << bucket_log_height("Global", false);
        let mut sides = edges(side_cap);
        sides.insert(0);
        let mut pairs: Vec<(usize, usize)> = sides
            .iter()
            .flat_map(|&init| sides.iter().map(move |&fin| (init, fin)))
            .collect();
        for p in (0..usize::BITS).map(|k| 1usize << k) {
            pairs.extend(
                sides
                    .iter()
                    .filter(|&&init| init <= p)
                    .map(|&init| (init, p - init)),
            );
        }
        let mut full_tables = 0usize;
        for (init, fin) in pairs {
            let events = init + fin;
            if events == 0 || init > side_cap || fin > side_cap || events > global_rows_cap {
                continue;
            }
            let mut natural = vec![("Global", events)];
            natural.extend((init > 0).then_some(("MemoryInitialize", init)));
            natural.extend((fin > 0).then_some(("MemoryFinalize", fin)));
            let shape = select_deferred(&natural);
            assert_eq!(shape["Global"], MLE_GLOBAL_LOG_HEIGHT);
            full_tables += usize::from(events == global_rows_cap);
        }
        assert!(full_tables > 0, "the sweep never filled the Global table");
    }

    /// The whitelist's size, pinned where no artifact is needed: a shape-table change moves this
    /// literal with it, together with the headroom figures on `MLE_VK_MERKLE_DEPTH`. `vk_map`'s
    /// shipped-artifact test derives the same count from the config and holds the artifact to it.
    #[test]
    fn the_whitelist_shape_count_is_pinned() {
        assert_eq!(mle_riscv_shapes().len(), 4_737, "riscv whitelist shapes");
    }

    /// A core chunk takes its ladder row at the smallest `MemoryUnaligned` height that holds its
    /// misaligned accesses, on each side of every height, and the shape it takes is a whitelist
    /// shape. Past the most the chunk split lets a chunk hold, no shape holds it.
    #[test]
    fn a_core_chunk_takes_the_smallest_unaligned_height_that_holds_it() {
        let mut natural: BTreeMap<String, usize> = MLE_CORE_LADDER[0]
            .iter()
            .map(|(name, log)| (name.to_string(), 1usize << log))
            .collect();
        let most = 1usize << MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT;
        let mut cases = vec![(0, 10), (1, 10)];
        for pair in MLE_MEMORY_UNALIGNED_LOG_HEIGHTS.windows(2) {
            cases.push((1 << pair[0], pair[0]));
            cases.push(((1 << pair[0]) + 1, pair[1]));
        }
        cases.push((most, MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT));
        for (rows, want) in cases {
            natural.insert("MemoryUnaligned".to_string(), rows);
            let (rung, mut shape) = select_core_rung(&natural).expect("row 0 holds the chunk");
            assert_eq!(rung, 0, "{rows} misaligned accesses");
            let got = shape
                .iter()
                .find(|(n, _)| n == "MemoryUnaligned")
                .unwrap()
                .1;
            assert_eq!(got, want, "{rows} misaligned accesses");
            shape.sort();
            assert!(
                whitelist_shapes().contains(&shape),
                "{rows}: not a whitelist shape"
            );
        }
        natural.insert("MemoryUnaligned".to_string(), most + 1);
        assert!(select_core_rung(&natural).is_none());
    }

    /// The global LogUp reads every chunk's event table at one height, the production operating
    /// point's: every shape the whitelist admits carries the Global AIR once, at that height.
    /// (The convert program does not build over any other, so a shape off it could have no leaf.)
    #[test]
    fn every_whitelist_shape_has_the_global_table_at_its_height() {
        let height = pico_mle_core::global_logup::global_log_height_at(
            crate::mle::machine::riscv::DEFAULT_LOG_STACKED_HEIGHT,
        );
        for (label, shape) in mle_riscv_shapes() {
            let global: Vec<usize> = shape
                .iter()
                .filter(|(name, _)| name == "Global")
                .map(|(_, log)| *log)
                .collect();
            assert_eq!(global, [height], "shape `{label}`");
        }
    }

    /// The whitelist builder checkpoints keygens by shape CONTENT, so two admitted shapes must
    /// never share a content key -- they would collapse into one leaf.
    #[test]
    fn every_whitelist_shape_has_a_unique_content_key() {
        use crate::mle::machine::vk_map::shape_content_key;
        let shapes = mle_riscv_shapes();
        let keys: std::collections::BTreeSet<String> =
            shapes.iter().map(|(_, s)| shape_content_key(s)).collect();
        assert_eq!(
            keys.len(),
            shapes.len(),
            "two whitelist shapes share a content key"
        );
        let labels: std::collections::BTreeSet<&str> =
            shapes.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(
            labels.len(),
            shapes.len(),
            "two whitelist shapes share a label"
        );
    }

    /// Every ladder row has to prove on a card at each `MemoryUnaligned` height it takes: TI =
    /// sum(interactions x height) over the row's chips must stay under 2^29, where the GKR size m
    /// goes from 29 to 30 and the leaf buffer outgrows the card. The interaction counts come off
    /// a real keygen, so a chip that gains an interaction moves the rows here rather than at
    /// proving time. And a row stops below 2^19 only where the next height would cross the line.
    #[test]
    fn core_ladder_rows_stay_under_the_gpu_line() {
        use crate::mle::machine::riscv::{
            air_id_for, mle_riscv_air_refs, Engine, RISCV_APP_PREP_AIR_IDS,
        };
        use pico_mle_core::{config::riscv_params_with_128_bits_security, StarkEngine};
        let engine: Engine = StarkEngine::new(riscv_params_with_128_bits_security(22));
        let program = Program {
            instructions: vec![crate::compiler::riscv::instruction::Instruction::new(
                crate::compiler::riscv::opcode::Opcode::ADD,
                0,
                0,
                0,
                false,
                false,
            )]
            .into(),
            pc_start: 0,
            pc_base: 0,
            memory_image: Default::default(),
            preprocessed_shape: None,
            profiled_functions: Default::default(),
        };
        let airs = mle_riscv_air_refs(Arc::new(program), true);
        let (_, vk) = engine.keygen_with_app_prep_and_required(
            &airs,
            RISCV_APP_PREP_AIR_IDS,
            crate::mle::machine::riscv::RISCV_REQUIRED_AIR_IDS,
        );
        let ti = |row: &[(String, usize)]| -> u64 {
            row.iter()
                .map(|(name, log)| {
                    let id = air_id_for(name).unwrap_or_else(|| panic!("no air id for {name}"));
                    vk.inner.per_air[id].num_interactions() as u64 * (1u64 << log)
                })
                .sum()
        };
        for (r, unaligned, row) in core_rungs() {
            let ti = ti(&row);
            eprintln!(
                "core ladder row {r}, MemoryUnaligned 2^{unaligned}: TI {:.4} x 2^29",
                ti as f64 / (1u64 << 29) as f64
            );
            assert!(
                ti < 1 << 29,
                "core ladder row {r} with MemoryUnaligned at 2^{unaligned}: TI = {ti} = {:.3} x \
                 2^29 crosses the GPU line",
                ti as f64 / (1u64 << 29) as f64
            );
        }
        for (r, class) in MLE_CORE_LADDER.iter().enumerate() {
            let most = class
                .iter()
                .find(|(n, _)| *n == "MemoryUnaligned")
                .unwrap()
                .1;
            let Some(&next) = MLE_MEMORY_UNALIGNED_LOG_HEIGHTS
                .iter()
                .find(|log| **log > most)
            else {
                continue;
            };
            let ti = ti(&core_rung_shape(class, next));
            assert!(
                ti >= 1 << 29,
                "core ladder row {r} stops at MemoryUnaligned 2^{most}, but 2^{next} keeps it at \
                 {:.3} x 2^29",
                ti as f64 / (1u64 << 29) as f64
            );
        }
    }

    /// The envelope row indices must name rows of the ladder, in ladder order, or the run log
    /// would attribute a chunk to a row that does not exist.
    #[test]
    fn envelope_rows_are_ladder_rows() {
        for &r in MLE_CORE_ENVELOPE_ROWS {
            assert!(
                r < MLE_CORE_LADDER.len(),
                "envelope row {r} is past the ladder"
            );
        }
        assert!(
            MLE_CORE_ENVELOPE_ROWS.windows(2).all(|w| w[0] < w[1]),
            "envelope rows are listed in ladder order"
        );
    }

    /// `select_convert_row` takes the first row that holds a program and relies on the last row
    /// holding everything the whitelist admits, so every row must sit under the last one
    /// componentwise and name exactly the same chips; a row that named a chip the others do
    /// not would leave that chip without a height on the other rows.
    #[test]
    fn convert_ladder_rows_close_under_the_last() {
        let last = MLE_RECURSION_CONVERT_LADDER
            .last()
            .expect("the convert ladder is empty");
        fn names(row: &[(&str, usize)]) -> std::collections::BTreeSet<String> {
            row.iter().map(|(n, _)| n.to_string()).collect()
        }
        for (r, row) in MLE_RECURSION_CONVERT_LADDER.iter().enumerate() {
            assert_eq!(
                names(row),
                names(last),
                "convert row {r} names another chip set"
            );
            for (name, log) in row.iter() {
                let cap = last
                    .iter()
                    .find(|(n, _)| n == name)
                    .map(|(_, h)| *h)
                    .unwrap();
                assert!(
                    *log <= cap,
                    "convert row {r}: {name} 2^{log} sits above the last row's 2^{cap}"
                );
            }
        }
    }

    /// The config digest is a pure function of the tables; the same binary must always produce
    /// the same one, or an artifact could be refused by the very build that made it.
    #[test]
    fn config_digest_is_stable() {
        assert_eq!(mle_shape_config_digest(), mle_shape_config_digest());
    }

    /// A memory chunk raises one cross-chunk event per memory event, so neither side's ceiling
    /// may stand above the Global table: under the 2^22 memory-event cap the finalize side holds
    /// at most 2^22 - 4 events (four buckets) and the initialize side at most the same.
    #[test]
    fn memory_pair_fits_under_global() {
        let global = bucket_log_height("Global", false);
        assert_eq!(global, MLE_GLOBAL_LOG_HEIGHT);
        assert!(bucket_log_height("MemoryInitialize", false) <= global);
        assert!(bucket_log_height("MemoryFinalize", false) <= global);
    }
}
