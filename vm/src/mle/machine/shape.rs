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
//!   - `Global == Poseidon2 + 2`, because the Global chip raises one Poseidon2 event per global
//!     event and the Poseidon2 chip packs `RISCV_POSEIDON2_DATAPAR = 4` of them per row;
//!   - `MemoryInitialize` and `MemoryFinalize` are each at most 2^22 in a deferred memory chunk
//!     because the emulator buckets each stream in `DEFERRED_MEMORY_BUCKET = 2^20 - 1` events
//!     (`record.rs`) and closes every memory record under the 2^22 event cap: at most four
//!     finalize buckets (2^22 - 4 events) per record, the initialize buckets riding on the last
//!     one under the same cap. Global, one row per memory event plus the padding row, then
//!     reaches 2^22;
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
    ("SyscallRiscv", 22),
    ("Ecall", 22),
    // Global carries every chunk kind and is the tallest chip in all three families;
    // Poseidon2 sits exactly 2 below it (RISCV_POSEIDON2_DATAPAR = 4).
    ("Global", 23),
    ("RiscvKoalaBearPoseidon2", 21),
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
    ("KeccakPermute", 20),
    ("ShaExtend", 20),
    ("ShaCompress", 20),
    // Control siblings and the precompile syscall receiver follow
    // `get_precompile_shapes`: ceil(2^h / rows_per_event), rounded up to a power of two.
    ("KeccakControl", 16),
    ("ShaExtendControl", 15),
    ("ShaCompressControl", 14),
    ("SyscallPrecompile", 17), // the 1-row/event kinds at 2^17 dominate here
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
];

/// The floor every present air pads to: `2^l_skip` rows, the smallest the MLE prover packs.
pub const MLE_MIN_LOG_HEIGHT: usize = 4;

/// `MemoryLocal` in a CPU chunk: its local-memory traffic scales with the instruction count.
pub const MEMORY_LOCAL_CPU_LOG_HEIGHT: usize = 22;

/// `MemoryLocal` in a deferred chunk: the ceiling `get_precompile_shapes` derives from
/// Global's own 2^23 cap, `ceil((2^23 / 2) / LOCAL_MEMORY_DATAPAR)`.
pub const MEMORY_LOCAL_DEFERRED_LOG_HEIGHT: usize = 20;

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
    "SyscallRiscv",
    "Ecall",
    "Global",
    "RiscvKoalaBearPoseidon2",
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

/// The core family's height ladder: 24 classes fitted to 60 of the 80-block p99 corpus (2,442
/// core chunks, 840 distinct height vectors) by agglomerative clustering, each class being the
/// componentwise maximum of its members, plus three envelope rows (a 3-class clustering of the
/// same set, with headroom on the cheap chips) for a core chunk no class covers. The other 20
/// blocks were held out: every one of their 833 core chunks lands on a class or an envelope row.
///
/// A chunk takes the FIRST entry that dominates it componentwise, and the rows sit
/// cheapest-first by the priced cost of a chunk on that row, so the first dominating row is the
/// cheapest one; the catch-all (not listed here, it is [`MLE_RISCV_MAIN_LOG_HEIGHTS`]) comes
/// last. Every row keeps TI = sum(interactions x height) under 2^29: at 2^29 the GKR size m goes
/// from 29 to 30 and the leaf buffer no longer fits a card, so a row past it would be CPU-only
/// (`core_ladder_rows_stay_under_the_gpu_line`). The 60-block envelope alone crosses that line,
/// which is why it is three rows and not one.
///
/// Under canonical presence a class is one whole height vector, hence one whitelist entry -- K
/// is bounded by keygen time, not by the whitelist budget. Priced on the held-out blocks the
/// ladder costs +1.1% of the natural riscv time.
///
/// Byte is a fixed-height table and Program is machine-wide, so both are the same in every row.
///
/// The three envelope rows sit at [`MLE_CORE_ENVELOPE_ROWS`]; sorted by price they land between
/// the classes, so a chunk a class holds can still take an envelope row that is cheaper and
/// also holds it.
pub const MLE_CORE_LADDER: &[&[(&str, usize)]] = &[
    // row 0: 17 of the 2,442 fit-set core chunks; 0.129 s; TI 0.18 x 2^29
    &[
        ("Cpu", 21),
        ("MemoryReadWrite", 20),
        ("Add", 20),
        ("Sub", 15),
        ("LessThan", 19),
        ("Bitwise", 18),
        ("ShiftLeft", 17),
        ("ShiftRight", 17),
        ("Mul", 13),
        ("Addw", 13),
        ("Subw", 4),
        ("DivRem", 4),
        ("SyscallRiscv", 12),
        ("Ecall", 12),
        ("MemoryLocal", 16),
        ("Global", 19),
        ("RiscvKoalaBearPoseidon2", 17),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 1: 16 of the 2,442 fit-set core chunks; 0.234 s; TI 0.36 x 2^29
    &[
        ("Cpu", 22),
        ("MemoryReadWrite", 21),
        ("Add", 21),
        ("Sub", 16),
        ("LessThan", 20),
        ("Bitwise", 19),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 14),
        ("Addw", 14),
        ("Subw", 4),
        ("DivRem", 4),
        ("SyscallRiscv", 13),
        ("Ecall", 13),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 2: 67 of the 2,442 fit-set core chunks; 0.330 s; TI 0.58 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 17),
        ("Addw", 17),
        ("Subw", 10),
        ("DivRem", 9),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 16),
        ("Global", 19),
        ("RiscvKoalaBearPoseidon2", 17),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 3: 268 of the 2,442 fit-set core chunks; 0.337 s; TI 0.61 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 16),
        ("Addw", 15),
        ("Subw", 12),
        ("DivRem", 10),
        ("SyscallRiscv", 11),
        ("Ecall", 11),
        ("MemoryLocal", 15),
        ("Global", 18),
        ("RiscvKoalaBearPoseidon2", 16),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 4: 110 of the 2,442 fit-set core chunks; 0.340 s; TI 0.63 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 15),
        ("Subw", 13),
        ("DivRem", 12),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 15),
        ("Global", 18),
        ("RiscvKoalaBearPoseidon2", 16),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 5: 172 of the 2,442 fit-set core chunks; 0.342 s; TI 0.65 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 18),
        ("Addw", 15),
        ("Subw", 14),
        ("DivRem", 12),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 15),
        ("Global", 18),
        ("RiscvKoalaBearPoseidon2", 16),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 6: 122 of the 2,442 fit-set core chunks; 0.352 s; TI 0.59 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 18),
        ("Subw", 11),
        ("DivRem", 10),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 7: 64 of the 2,442 fit-set core chunks; 0.353 s; TI 0.69 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 19),
        ("Addw", 16),
        ("Subw", 14),
        ("DivRem", 13),
        ("SyscallRiscv", 15),
        ("Ecall", 15),
        ("MemoryLocal", 15),
        ("Global", 18),
        ("RiscvKoalaBearPoseidon2", 16),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 8: 226 of the 2,442 fit-set core chunks; 0.354 s; TI 0.64 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 16),
        ("Subw", 13),
        ("DivRem", 12),
        ("SyscallRiscv", 15),
        ("Ecall", 15),
        ("MemoryLocal", 16),
        ("Global", 19),
        ("RiscvKoalaBearPoseidon2", 17),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 9: 180 of the 2,442 fit-set core chunks; 0.360 s; TI 0.61 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 15),
        ("Addw", 16),
        ("Subw", 9),
        ("DivRem", 4),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 10: 118 of the 2,442 fit-set core chunks; 0.364 s; TI 0.68 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 18),
        ("Addw", 17),
        ("Subw", 14),
        ("DivRem", 13),
        ("SyscallRiscv", 16),
        ("Ecall", 16),
        ("MemoryLocal", 16),
        ("Global", 19),
        ("RiscvKoalaBearPoseidon2", 17),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 11: 76 of the 2,442 fit-set core chunks; 0.380 s; TI 0.65 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 22),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 14),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 4),
        ("SyscallRiscv", 14),
        ("Ecall", 14),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 12: 69 of the 2,442 fit-set core chunks; 0.385 s; TI 0.67 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 22),
        ("Bitwise", 19),
        ("ShiftLeft", 21),
        ("ShiftRight", 21),
        ("Mul", 11),
        ("Addw", 13),
        ("Subw", 6),
        ("DivRem", 4),
        ("SyscallRiscv", 10),
        ("Ecall", 10),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 13: 300 of the 2,442 fit-set core chunks; 0.386 s; TI 0.68 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 17),
        ("Addw", 18),
        ("Subw", 13),
        ("DivRem", 14),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 14: envelope row: coarse class max + headroom; 0.387 s; TI 0.77 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
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
        ("Global", 19),
        ("RiscvKoalaBearPoseidon2", 17),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 15: 79 of the 2,442 fit-set core chunks; 0.394 s; TI 0.70 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 17),
        ("Addw", 18),
        ("Subw", 13),
        ("DivRem", 11),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 16: 84 of the 2,442 fit-set core chunks; 0.397 s; TI 0.60 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 21),
        ("Sub", 15),
        ("LessThan", 19),
        ("Bitwise", 19),
        ("ShiftLeft", 18),
        ("ShiftRight", 16),
        ("Mul", 14),
        ("Addw", 18),
        ("Subw", 10),
        ("DivRem", 9),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 17: 51 of the 2,442 fit-set core chunks; 0.406 s; TI 0.62 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 21),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 18),
        ("ShiftRight", 18),
        ("Mul", 16),
        ("Addw", 18),
        ("Subw", 11),
        ("DivRem", 9),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 18: 20 of the 2,442 fit-set core chunks; 0.415 s; TI 0.77 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 22),
        ("Bitwise", 21),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 19),
        ("Addw", 17),
        ("Subw", 14),
        ("DivRem", 16),
        ("SyscallRiscv", 16),
        ("Ecall", 16),
        ("MemoryLocal", 17),
        ("Global", 20),
        ("RiscvKoalaBearPoseidon2", 18),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 19: 88 of the 2,442 fit-set core chunks; 0.421 s; TI 0.66 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 19),
        ("Bitwise", 19),
        ("ShiftLeft", 18),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 17),
        ("Subw", 12),
        ("DivRem", 12),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 20: 170 of the 2,442 fit-set core chunks; 0.434 s; TI 0.70 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 21),
        ("Sub", 18),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 19),
        ("Mul", 18),
        ("Addw", 17),
        ("Subw", 13),
        ("DivRem", 11),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 21: 90 of the 2,442 fit-set core chunks; 0.441 s; TI 0.72 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 20),
        ("ShiftLeft", 20),
        ("ShiftRight", 19),
        ("Mul", 16),
        ("Addw", 17),
        ("Subw", 11),
        ("DivRem", 4),
        ("SyscallRiscv", 15),
        ("Ecall", 15),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 22: 14 of the 2,442 fit-set core chunks; 0.455 s; TI 0.78 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 22),
        ("Sub", 19),
        ("LessThan", 21),
        ("Bitwise", 21),
        ("ShiftLeft", 20),
        ("ShiftRight", 20),
        ("Mul", 19),
        ("Addw", 16),
        ("Subw", 14),
        ("DivRem", 9),
        ("SyscallRiscv", 16),
        ("Ecall", 16),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 23: 26 of the 2,442 fit-set core chunks; 0.473 s; TI 0.78 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 23),
        ("Add", 21),
        ("Sub", 17),
        ("LessThan", 20),
        ("Bitwise", 20),
        ("ShiftLeft", 19),
        ("ShiftRight", 18),
        ("Mul", 17),
        ("Addw", 17),
        ("Subw", 12),
        ("DivRem", 10),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 18),
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 24: envelope row: coarse class max + headroom; 0.491 s; TI 0.90 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
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
        ("Global", 21),
        ("RiscvKoalaBearPoseidon2", 19),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 25: 15 of the 2,442 fit-set core chunks; 0.525 s; TI 0.72 x 2^29
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 22),
        ("Add", 20),
        ("Sub", 16),
        ("LessThan", 19),
        ("Bitwise", 20),
        ("ShiftLeft", 17),
        ("ShiftRight", 17),
        ("Mul", 16),
        ("Addw", 16),
        ("Subw", 10),
        ("DivRem", 4),
        ("SyscallRiscv", 17),
        ("Ecall", 17),
        ("MemoryLocal", 19),
        ("Global", 22),
        ("RiscvKoalaBearPoseidon2", 20),
        ("Byte", 17),
        ("Program", 20),
    ],
    // row 26: envelope row: coarse class max + headroom; TI 0.765 x 2^29. Ecall is at 2^18 because
    // a G1MSM chunk (block 26180455, 139,646 ecalls) fits no other row and was past 2^17 here.
    &[
        ("Cpu", 23),
        ("MemoryReadWrite", 23),
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
        ("Global", 22),
        ("RiscvKoalaBearPoseidon2", 20),
        ("Byte", 17),
        ("Program", 20),
    ],
];

/// The rows of [`MLE_CORE_LADDER`] that are envelope rows (a coarse 3-class clustering of the fit
/// set with headroom) rather than fitted classes; the run log names them so a run's cost can be
/// attributed to them.
pub const MLE_CORE_ENVELOPE_ROWS: &[usize] = &[14, 24, 26];

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
    pub global: usize,
    pub poseidon2: usize,
}

/// The control sibling a compute kind emits alongside itself, one row per parent event.
fn precompile_control_sibling(kind: &str) -> Option<&'static str> {
    match kind {
        "ShaCompress" => Some("ShaCompressControl"),
        "ShaExtend" => Some("ShaExtendControl"),
        "KeccakPermute" => Some("KeccakControl"),
        _ => None,
    }
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

/// Every shape the precompile family admits.
///
/// A precompile chunk has TWO free variables, not one. The event count `n` of the compute kind
/// drives the kind's own height (`n * rows_per_event`) and, one row per event, its syscall and
/// control siblings. But MemoryLocal counts the DISTINCT ADDRESSES the chunk touches, which
/// address locality decides, not `n`: the corpus pins no per-event constant that explains it,
/// and for Uint256MulMod the bracket its rows imply is empty. So MemoryLocal is swept, bounded
/// above by what the airs can possibly raise -- `n * (rows_per_event * lookups_per_row +
/// control_lookups_per_row)` -- and below by the `2^l_skip` floor.
///
/// Everything else follows. Global counts `2 * local + n` bus events plus the one padding row
/// its accumulation constraints need, so given the two swept heights it takes exactly two
/// consecutive log values: the interval the raw count can land in spans a factor of two. And
/// Poseidon2 packs `RISCV_POSEIDON2_DATAPAR` global events per row, so it sits two below Global
/// whenever that leaves it above the floor -- three when the event count is exactly a power of
/// two, where Global's padding row alone takes it to the next power. `select_riscv_shape` pads
/// Poseidon2 back up to two below in that case, so the three-below vector is not listed.
///
/// Heights are capped by the family catch-all, which bounds every reachable chunk; a point above
/// it is unreachable and is dropped rather than clamped, so nothing here exceeds it.
pub fn mle_precompile_shapes() -> Vec<MlePrecompileShape> {
    use crate::{
        instances::{
            chiptype::riscv_chiptype::RiscvChipType,
            compiler::shapes::riscv_shape::precompile_rows_per_event,
        },
        primitives::consts::{LOCAL_MEMORY_DATAPAR, RISCV_POSEIDON2_DATAPAR},
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
        let global_cap = bucket_log_height("Global", false);
        let poseidon2_cap = bucket_log_height("RiscvKoalaBearPoseidon2", false);
        let control_cap = control.map(|c| bucket_log_height(c, false));

        for kind_log_height in MLE_MIN_LOG_HEIGHT..=kind_cap {
            // Event counts this kind height admits: the kind air pads `n * rows_per_event` up to
            // `2^kind_log_height`, so `n` spans a factor of two (clipped at the floor).
            let rows_hi = 1u128 << kind_log_height;
            let rows_lo = if kind_log_height == MLE_MIN_LOG_HEIGHT {
                1
            } else {
                (1u128 << (kind_log_height - 1)) + 1
            };
            let n_hi = rows_hi / rows_per_event;
            let n_lo = rows_lo.div_ceil(rows_per_event).max(1);
            if n_hi < n_lo {
                continue;
            }
            for syscall in [log2_ceil(n_lo), log2_ceil(n_hi)] {
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
                    // `+ 1`: the Global trace always ends with one padding row. Away from the
                    // floor the raw count spans a factor of two and this is two values; at the
                    // floor both windows are wider, so the whole range is walked.
                    let g_lo = log2_ceil(2 * l_lo + s_lo + 1);
                    let g_hi = log2_ceil(2 * l_hi + s_hi + 1);
                    for global in g_lo..=g_hi {
                        let poseidon2 = global
                            .saturating_sub(RISCV_POSEIDON2_DATAPAR.ilog2() as usize)
                            .max(MLE_MIN_LOG_HEIGHT);
                        if global > global_cap || poseidon2 > poseidon2_cap {
                            continue;
                        }
                        out.push(MlePrecompileShape {
                            kind: kind.clone(),
                            kind_log_height,
                            control: control.map(|c| (c.to_string(), syscall)),
                            syscall_precompile: syscall,
                            memory_local,
                            global,
                            poseidon2,
                        });
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Every riscv shape the whitelist admits, labelled by family, in a stable order.
///
/// This is the enumeration `build_vk_map` keys the whitelist on and the tier probe walks: the
/// core ladder with its catch-all behind it, the memory family's free product, and the
/// precompile family's per-kind sweep. Byte and Program are pinned machine-wide and appear in
/// every shape.
pub fn mle_riscv_shapes() -> Vec<(String, Vec<(String, usize)>)> {
    let byte = ("Byte".to_string(), bucket_log_height("Byte", false));
    let program = ("Program".to_string(), bucket_log_height("Program", false));
    let mut out = Vec::new();

    for (i, class) in MLE_CORE_LADDER.iter().enumerate() {
        out.push((
            format!("core:class{i}"),
            class.iter().map(|(n, h)| (n.to_string(), *h)).collect(),
        ));
    }
    out.push((
        "core:catch-all".to_string(),
        MLE_CORE_CANONICAL_PRESENCE
            .iter()
            .map(|n| (n.to_string(), bucket_log_height(n, true)))
            .collect(),
    ));

    // Memory: MemoryInitialize and MemoryFinalize each absent or anywhere in range, Global free
    // over its own, Poseidon2 pinned under it. Both absent is not a memory shape at all.
    let gap = crate::primitives::consts::RISCV_POSEIDON2_DATAPAR.ilog2() as usize;
    let init_cap = bucket_log_height("MemoryInitialize", false);
    let final_cap = bucket_log_height("MemoryFinalize", false);
    let global_cap = bucket_log_height("Global", false);
    for init in (MLE_MIN_LOG_HEIGHT..=init_cap).map(Some).chain([None]) {
        for fin in (MLE_MIN_LOG_HEIGHT..=final_cap).map(Some).chain([None]) {
            if init.is_none() && fin.is_none() {
                continue;
            }
            for global in MLE_MIN_LOG_HEIGHT..=global_cap {
                let mut shape = vec![byte.clone(), program.clone()];
                if let Some(h) = init {
                    shape.push(("MemoryInitialize".to_string(), h));
                }
                if let Some(h) = fin {
                    shape.push(("MemoryFinalize".to_string(), h));
                }
                shape.push(("Global".to_string(), global));
                shape.push((
                    "RiscvKoalaBearPoseidon2".to_string(),
                    global.saturating_sub(gap).max(MLE_MIN_LOG_HEIGHT),
                ));
                out.push((
                    format!(
                        "memory:{}/{}/{global}",
                        init.map_or("-".to_string(), |h| h.to_string()),
                        fin.map_or("-".to_string(), |h| h.to_string())
                    ),
                    shape,
                ));
            }
        }
    }

    for s in mle_precompile_shapes() {
        let mut shape = vec![
            byte.clone(),
            program.clone(),
            (s.kind.clone(), s.kind_log_height),
            ("SyscallPrecompile".to_string(), s.syscall_precompile),
            ("MemoryLocal".to_string(), s.memory_local),
            ("Global".to_string(), s.global),
            ("RiscvKoalaBearPoseidon2".to_string(), s.poseidon2),
        ];
        if let Some((name, h)) = s.control.clone() {
            shape.push((name, h));
        }
        out.push((
            format!(
                "precompile:{}:{}/{}/{}/{}",
                s.kind, s.kind_log_height, s.syscall_precompile, s.memory_local, s.global
            ),
            shape,
        ));
    }
    out
}

/// A digest of the whole shape config: every riscv shape the whitelist admits, the convert
/// ladder rows and the combine and embed tier tables, and the Merkle depth. The vk-map artifact
/// carries it, and loading an artifact under a binary whose config digests differently is
/// refused -- a whitelist built from
/// one shape config must not be used to prove under another, since the enumeration order, the
/// tier tables and the depth all shape the leaves.
///
/// Field-native: each shape is its `(air id, log height)` pairs sorted by air id, length-prefixed;
/// then the convert row count and each tier table's heights in table order, length-prefixed;
/// then the depth. Sponge-hashed
/// with the same padding-free sponge the leaves use.
pub fn mle_shape_config_digest() -> [Kb; 8] {
    use crate::mle::machine::{exe::sponge_hash, riscv::air_name, vk_map::MLE_VK_MERKLE_DEPTH};
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
        MLE_RECURSION_COMBINE_LOG_HEIGHTS,
        MLE_RECURSION_EMBED_LOG_HEIGHTS,
    ]) {
        pre.push(Kb::from_u32(table.len() as u32));
        pre.extend(table.iter().map(|(_, h)| Kb::from_u32(*h as u32)));
    }
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
/// postdates them and carries one row per ecall instruction. Global and Poseidon2 are then
/// overridden with the event vectors their generators actually read, `global_lookup_events`
/// and `poseidon2_events`, rather than the derivations those helpers make of them.
///
/// Byte and Program are left out: both are pinned machine-wide, so they never take part in a
/// match.
pub fn mle_natural_heights(record: &EmulationRecord) -> BTreeMap<String, usize> {
    use crate::{
        instances::chiptype::riscv_chiptype::RiscvChipType,
        primitives::consts::RISCV_POSEIDON2_DATAPAR,
    };

    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    if record.is_cpu_chunk {
        out.extend(RiscvChipType::<Kb>::riscv_heights(record));
        out.insert(
            "Ecall".to_string(),
            record
                .cpu_events
                .as_slice()
                .iter()
                .filter(|e| e.instruction.is_ecall_instruction())
                .count(),
        );
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
            instances::compiler::shapes::riscv_shape::precompile_rows_per_event,
            primitives::consts::LOCAL_MEMORY_DATAPAR,
        };
        for kind in precompile_kinds() {
            let Some((kind_rows, local_mem_events, _)) =
                RiscvChipType::<Kb>::get_precompile_heights(kind, record)
            else {
                continue;
            };
            let events = kind_rows / precompile_rows_per_event(kind);
            if let Some(control) = precompile_control_sibling(kind) {
                out.insert(control.to_string(), events);
            }
            out.insert(kind.clone(), kind_rows);
            out.insert("SyscallPrecompile".to_string(), events);
            out.insert(
                "MemoryLocal".to_string(),
                local_mem_events.div_ceil(LOCAL_MEMORY_DATAPAR),
            );
            // `+ 1`: the Global trace always ends with one padding row.
            let global = 2 * local_mem_events + events + 1;
            out.insert("Global".to_string(), global);
            out.insert(
                "RiscvKoalaBearPoseidon2".to_string(),
                global.div_ceil(RISCV_POSEIDON2_DATAPAR),
            );
        }
    }
    // What the two generators read, whichever family: Global pads `events + 1` (its last row
    // must be padding), Poseidon2 packs `RISCV_POSEIDON2_DATAPAR` events per row.
    if out.contains_key("Global") {
        out.insert("Global".to_string(), record.global_lookup_events.len() + 1);
        out.insert(
            "RiscvKoalaBearPoseidon2".to_string(),
            record
                .poseidon2_events
                .len()
                .div_ceil(RISCV_POSEIDON2_DATAPAR),
        );
    }
    out
}

/// [`mle_natural_heights`] read off the GPU preparer's `EventCounter`, which already holds
/// every count the device kernels size their traces from, extra-record events included. Row for
/// row what `mle_natural_heights` returns on the augmented record, without that path's record
/// clone and host extra-record pass, and without its walks over the events: a core chunk's table
/// is rebuilt from the counter (the ecall count is taken over the CPU events in parallel); a
/// memory chunk's from the two event vectors' lengths; a precompile chunk's from the counter's
/// per-kind event and local-memory counts; Global and Poseidon2, the two heights extra-record
/// output feeds, come from the counter in every family. `MLE_SHAPE_CROSSCHECK=1` asserts the
/// equality on every chunk (`prepare_chunk_shaped`).
#[cfg(feature = "cuda-mle")]
pub fn mle_natural_heights_from_counter(
    record: &EmulationRecord,
    counter: &crate::instances::preparer::EventCounter,
) -> BTreeMap<String, usize> {
    use crate::primitives::consts::{
        ADD_DATAPAR, BITWISE_DATAPAR, DIVREM_DATAPAR, LOCAL_MEMORY_DATAPAR, LT_DATAPAR,
        MEMORY_RW_DATAPAR, MUL_DATAPAR, RISCV_POSEIDON2_DATAPAR, SLL_DATAPAR, SR_DATAPAR,
        SUB_DATAPAR,
    };
    if !record.is_cpu_chunk {
        // The deferred families, off the counter: `mle_natural_heights` walks every precompile
        // event's local memory accesses to count them, which on a keccak chunk is hundreds of
        // milliseconds on the preparer lane, while the packaging already counted exactly that
        // (`get_precompile_local_mem_len`, the same expression). Same map as the record walk,
        // row for row; `MLE_SHAPE_CROSSCHECK=1` asserts it.
        use crate::{
            instances::compiler::shapes::riscv_shape::{
                precompile_rows_per_event, precompile_syscall_code,
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
                out.insert(kind.clone(), events * precompile_rows_per_event(kind));
                out.insert("SyscallPrecompile".to_string(), events);
                out.insert(
                    "MemoryLocal".to_string(),
                    local_mem_events.div_ceil(LOCAL_MEMORY_DATAPAR),
                );
            }
        }
        // What the two generators read, whichever family: Global pads `events + 1` (its last
        // row must be padding), Poseidon2 packs `RISCV_POSEIDON2_DATAPAR` events per row.
        out.insert("Global".to_string(), counter.num_global_lookup_events + 1);
        out.insert(
            "RiscvKoalaBearPoseidon2".to_string(),
            counter
                .num_poseidon2_events
                .div_ceil(RISCV_POSEIDON2_DATAPAR),
        );
        return out;
    }
    // One row per ecall instruction: counted over the CPU events in parallel, as the CPU chip's
    // own extra-record count is -- a serial pass over a full chunk's events is ~60 ms on the
    // preparer lane, which the provers then wait for.
    let ecalls = {
        use crate::iter::{PicoIterator, PicoSlice};
        let events = record.cpu_events.as_slice();
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        events
            .pico_chunks(chunk_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .filter(|e| e.instruction.is_ecall_instruction())
                    .count()
            })
            .pico_reduce(|| 0, |a, b| a + b)
    };
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
        // `+ 1`: the Global trace always ends with one padding row.
        ("Global", counter.num_global_lookup_events + 1),
        (
            "RiscvKoalaBearPoseidon2",
            counter
                .num_poseidon2_events
                .div_ceil(RISCV_POSEIDON2_DATAPAR),
        ),
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
        for (i, class) in MLE_CORE_LADDER.iter().enumerate() {
            if dominates(class) {
                return Some((i, class.iter().map(|(n, h)| (n.to_string(), *h)).collect()));
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

/// Whether a core shape is the catch-all row: every air at its `MLE_RISCV_MAIN_LOG_HEIGHTS`
/// height. The catch-all is a CPU-only shape (its GKR leaf buffer is 64 GiB), so a GPU prover
/// asks this before it commits to a chunk.
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
/// two a trace pads to anyway. The one exception is Poseidon2, which the enumerations pin two
/// below Global, and which [`pad_poseidon2_under_global`] lifts there when it falls three below.
/// Byte and Program are pinned machine-wide in all three.
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
            r if MLE_CORE_ENVELOPE_ROWS.contains(&r) => format!("envelope{r}"),
            r => format!("class{r}"),
        };
        tracing::info!(target: "mle_shape", "core chunk takes rung {name}");
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
            (name.clone(), log)
        })
        .collect();
    pad_poseidon2_under_global(&mut shape);
    assert_whitelist_shape(&shape, natural);
    shape
}

/// Pad a deferred chunk's Poseidon2 up to two below its Global, the height the memory and
/// precompile enumerations give it.
///
/// Global has a row per global event plus one padding row; Poseidon2 has a row per
/// `RISCV_POSEIDON2_DATAPAR` events and no padding row. So Poseidon2 sits two below Global,
/// except when the event count is exactly a power of two: then the padding row alone lifts Global
/// to the next power, and Poseidon2 sits three below. No enumeration lists that height vector, so
/// its convert key is not in the whitelist, and the chunk's parent combine finds a child key it
/// cannot prove membership of. A taller trace is always admissible, and the cost is one
/// Poseidon2 table of twice the height in the rare chunk this applies to.
fn pad_poseidon2_under_global(shape: &mut [(String, usize)]) {
    let gap = crate::primitives::consts::RISCV_POSEIDON2_DATAPAR.ilog2() as usize;
    let Some(global) = shape
        .iter()
        .find(|(name, _)| name == "Global")
        .map(|(_, log)| *log)
    else {
        return;
    };
    if let Some((_, poseidon2)) = shape
        .iter_mut()
        .find(|(name, _)| name == "RiscvKoalaBearPoseidon2")
    {
        *poseidon2 = (*poseidon2).max(global.saturating_sub(gap).max(MLE_MIN_LOG_HEIGHT));
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
/// child-shape base to exactly {C, B} and keeps the whitelist's shape product at 10 combine
/// entries. (FRI's closest-fit over a multi-shape allowed set is data-dependent, so its
/// whole cartesian product must be preregistered — see `get_all_shape_combinations`.)
/// The root is NOT a tier: it is just the last combine round with `is_complete = true`,
/// exactly as in the FRI path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecursionTier {
    /// A convert node, padded to this row of [`MLE_RECURSION_CONVERT_LADDER`].
    Convert(usize),
    Combine,
    /// The embed node, which re-proves the complete root under the outer BN254-hashed config.
    /// It had shared the combine tier, which meant tightening that table would silently have to
    /// hold for a program nobody had measured. Its own table starts as a copy of the combine
    /// values, so it keeps exactly the heights it has always run at until someone measures it.
    Embed,
}

/// Convert-tier log2 heights, as a ladder: a convert program takes the FIRST row that holds its
/// natural heights (`select_convert_row`), and the last row holds every shape the whitelist
/// admits, so selection always terminates. `convert_ladder_rows_close_under_the_last` holds the
/// rows under the last one; that the last row holds every whitelist shape is what the builder
/// and the tier probe assert (`check_recursion_tier` over the whole enumeration). Rows sit
/// cheapest first by stacked width W = sum(w_main * 2^h) / 2^21, the quantity the convert time
/// follows (~154 + 1.45 W ms on one card).
///
/// One tier for every child had to be the componentwise maximum over the whole enumeration,
/// W = 68, set by the core catch-all (Poseidon2Packed, ExtDotProduct, MemoryVar) and by keccak
/// at its cap (ExtAlu), while the children the corpus actually produces need W = 8..28: the
/// padding was 56% of the whitelist's E2E cost. With rows, each child pads to the nearest row
/// above it and the combine machine learns one child layout per row
/// (`preregister_standard_shapes`).
///
/// Row 0 (W 21) holds 14,832 of the 15,643 whitelist shapes, among them the core classes up
/// to class 21, the small precompile / memory children and all 519 shapes of the poseidon2 and
/// Ed25519 precompiles (air ids 47-49); row 1 (W 37) the five widest core
/// classes, the keccak and the large precompile children; row 2 (W 62) the catch-all and 59
/// more shapes no corpus block uses. Fitted over the 80-block p99 corpus, tier-probed on this
/// very config; `examples/mle_tier_probe.rs` walks every whitelist shape and reports which row it
/// takes and the slack it leaves.
///
/// Converts have no fixpoint concern: their children are RISC-V proofs, not recursion proofs.
pub const MLE_RECURSION_CONVERT_LADDER: &[&[(&str, usize)]] = &[
    // row 0: W = 21
    &[
        ("ExtAlu", 18),
        ("ExtDotProduct", 17),
        ("Poseidon2Packed", 17),
        ("MemoryVar", 16),
        ("HornerEval", 14),
        ("MemoryConst", 14),
        ("BaseAlu", 14),
        ("AssertZeroExt", 14),
        ("UnpackBlock", 15),
        ("ExpBitsLen", 14),
        ("MleOpen", 12),
        ("DigestSelect", 13),
        ("BinaryFoldStep", 13),
        ("PackBlock", 13),
        ("GkrSumcheckRound", 9),
        ("FracFold", 5),
        ("LagrangeEvalD2", 6),
        ("Select", 4),
        ("Poseidon2", 4),
        ("PublicValues", 4),
        ("UnivariateFold", 4),
    ],
    // row 1: W = 37
    &[
        ("ExtAlu", 19),
        ("ExtDotProduct", 17),
        ("Poseidon2Packed", 18),
        ("MemoryVar", 16),
        ("HornerEval", 14),
        ("MemoryConst", 14),
        ("BaseAlu", 14),
        ("AssertZeroExt", 14),
        ("UnpackBlock", 15),
        ("ExpBitsLen", 14),
        ("MleOpen", 13),
        ("DigestSelect", 13),
        ("BinaryFoldStep", 13),
        ("PackBlock", 13),
        ("GkrSumcheckRound", 9),
        ("FracFold", 5),
        ("LagrangeEvalD2", 6),
        ("Select", 4),
        ("Poseidon2", 4),
        ("PublicValues", 4),
        ("UnivariateFold", 4),
    ],
    // row 2: W = 62, the componentwise maximum over every whitelist shape. The peak is not
    // always the core child: ExtAlu, MleOpen and MemoryConst are set by the keccak one,
    // ExtDotProduct and MemoryVar by the core catch-all.
    &[
        ("ExtAlu", 19),
        ("ExtDotProduct", 18),
        ("Poseidon2Packed", 19),
        ("MemoryVar", 18),
        ("HornerEval", 14),
        ("MemoryConst", 14),
        ("BaseAlu", 14),
        ("AssertZeroExt", 14),
        ("UnpackBlock", 15),
        ("ExpBitsLen", 14),
        ("MleOpen", 13),
        ("DigestSelect", 13),
        ("BinaryFoldStep", 13),
        ("PackBlock", 13),
        ("GkrSumcheckRound", 9),
        ("FracFold", 5),
        ("LagrangeEvalD2", 6),
        ("Select", 4),
        ("Poseidon2", 4),
        ("PublicValues", 4),
        ("UnivariateFold", 4),
    ],
];

/// Combine-tier log2 heights, shared by EVERY combine node including the root (the last,
/// `is_complete = true` round): measured maxima over every such proof (children =
/// natural-height recursion proofs; tier-padded children and the membership circuit add a
/// little work — the pow2 slack absorbs it, and an overflow fails loudly with the chip's row
/// width in the panic).
///
/// Root proofs measured one notch below this table on several chips (the root proof is the
/// shipped artifact, so its padding is what the ~3% gap to the ~494K natural-height floor is
/// made of). If that margin is ever worth reclaiming, reintroduce a root-specific table:
/// role-based selection keeps the child-shape base at {C, B} (the root is never a child), so
/// the cost is a whitelist REBUILD, not more whitelist entries. Note the root's grammar-worst
/// case (verifying two convert-tier children in a 2-chunk tree) matches a combine node's, so
/// the shared table is the conservative choice.
pub const MLE_RECURSION_COMBINE_LOG_HEIGHTS: &[(&str, usize)] = &[
    ("ExtAlu", 17),
    ("HornerEval", 17),
    ("Poseidon2Packed", 17),
    // Follows the convert tier: a wider ExtDotProduct child pushes this to 34101 rows,
    // 1333 over 2^15.
    ("MemoryVar", 16),
    ("ExtDotProduct", 16),
    ("ExpBitsLen", 15),
    ("BaseAlu", 14),
    ("AssertZeroExt", 14),
    ("BinaryFoldStep", 14),
    // Combine verifies two recursion-proof children, so its EF-hint (now unpack_block) count is
    // ~2x convert's. Measured maximum over all covered combine shapes: 2^16.
    ("UnpackBlock", 15),
    ("MemoryConst", 13),
    ("DigestSelect", 13),
    ("PackBlock", 13),
    ("MleOpen", 12),
    ("GkrSumcheckRound", 10),
    ("FracFold", 6),
    ("LagrangeEvalD2", 6),
    ("Select", 4),
    ("Poseidon2", 4),
    ("PublicValues", 4),
    ("UnivariateFold", 4),
];
/// Embed-tier log2 heights. Started as a copy of the combine tier, which is where the embed
/// node ran before it had a tier of its own; the embed program has never been measured, so
/// these are inherited rather than derived. Measure it before trusting them as bounds.
pub const MLE_RECURSION_EMBED_LOG_HEIGHTS: &[(&str, usize)] = &[
    ("ExtAlu", 17),
    ("HornerEval", 17),
    ("Poseidon2Packed", 17),
    ("MemoryVar", 16),
    ("ExtDotProduct", 16),
    ("ExpBitsLen", 15),
    ("BaseAlu", 14),
    ("AssertZeroExt", 14),
    ("BinaryFoldStep", 14),
    ("UnpackBlock", 16),
    ("MemoryConst", 13),
    ("DigestSelect", 13),
    ("PackBlock", 13),
    ("MleOpen", 12),
    ("GkrSumcheckRound", 10),
    ("FracFold", 6),
    ("LagrangeEvalD2", 6),
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
        RecursionTier::Combine => MLE_RECURSION_COMBINE_LOG_HEIGHTS,
        RecursionTier::Embed => MLE_RECURSION_EMBED_LOG_HEIGHTS,
    };
    crate::instances::compiler::shapes::recursion_shape::RecursionPadShape {
        inner: table.iter().map(|(n, log)| (n.to_string(), *log)).collect(),
    }
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
        assert_eq!(seen, 50, "the machine's air list changed size");
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

    /// The program table's preprocessed height and its main multiplicity trace must agree.
    #[test]
    fn program_main_matches_its_preprocessed_height() {
        assert_eq!(
            bucket_log_height("Program", true),
            MLE_RISCV_PROGRAM_LOG_HEIGHT
        );
    }

    /// The Global chip raises one Poseidon2 event per global event and the Poseidon2 chip packs
    /// `RISCV_POSEIDON2_DATAPAR` of them per row, so the catch-all must keep that gap.
    #[test]
    fn poseidon2_sits_datapar_below_global() {
        let gap =
            bucket_log_height("Global", true) - bucket_log_height("RiscvKoalaBearPoseidon2", true);
        assert_eq!(
            1usize << gap,
            crate::primitives::consts::RISCV_POSEIDON2_DATAPAR
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

    /// The ladder must keep the Global / Poseidon2 relation the catch-all rests on. A class is
    /// the componentwise maximum of real chunks, which does not preserve a relation in general,
    /// so it is checked rather than assumed.
    #[test]
    fn core_ladder_keeps_the_poseidon2_gap() {
        let gap = crate::primitives::consts::RISCV_POSEIDON2_DATAPAR.ilog2() as usize;
        for (i, class) in MLE_CORE_LADDER.iter().enumerate() {
            let get = |n: &str| {
                class
                    .iter()
                    .find(|(m, _)| *m == n)
                    .map(|(_, h)| *h)
                    .unwrap()
            };
            assert_eq!(
                get("RiscvKoalaBearPoseidon2"),
                get("Global") - gap,
                "class {i}: Poseidon2 does not sit {gap} under Global"
            );
        }
    }

    /// Nothing the precompile generator emits may exceed the family catch-all: the ladder is
    /// only usable if the catch-all is still the last rung. `padding_shape` would otherwise be
    /// handed a shape it cannot pad down to.
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
            check("Global", s.global);
            check("RiscvKoalaBearPoseidon2", s.poseidon2);
            if let Some((name, h)) = &s.control {
                check(name, *h);
            }
        }
    }

    /// The generator must keep the two relations the catch-all is built on: Poseidon2 sits
    /// `log2(RISCV_POSEIDON2_DATAPAR)` below Global, and a control sibling emits one row per
    /// parent event, exactly as the syscall chip does.
    #[test]
    fn precompile_shapes_keep_the_structural_relations() {
        let gap = crate::primitives::consts::RISCV_POSEIDON2_DATAPAR.ilog2() as usize;
        for s in mle_precompile_shapes() {
            assert_eq!(
                s.poseidon2,
                s.global.saturating_sub(gap).max(MLE_MIN_LOG_HEIGHT),
                "{} 2^{}: Poseidon2 2^{} does not sit under Global 2^{}",
                s.kind,
                s.kind_log_height,
                s.poseidon2,
                s.global
            );
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

    /// Block 26200332, chunk 22: 8192 Secp256k1DoubleAssign events
    /// over 28,672 local addresses raise 2 * 28,672 + 8192 = 2^16 global events. Global's padding
    /// row takes it to 2^17 while Poseidon2 needs only 2^14, three below. No enumeration lists
    /// that vector, so the chunk's convert key was not in the whitelist and its parent combine
    /// panicked. Poseidon2 pads to 2^15, and the shape is a member.
    #[test]
    fn a_power_of_two_global_count_pads_poseidon2() {
        let shape = select_deferred(&[
            ("Secp256k1DoubleAssign", 8192),
            ("SyscallPrecompile", 8192),
            ("MemoryLocal", 7168),
            ("Global", 65_537),
            ("RiscvKoalaBearPoseidon2", 16_384),
        ]);
        assert_eq!(shape["Secp256k1DoubleAssign"], 13);
        assert_eq!(shape["SyscallPrecompile"], 13);
        assert_eq!(shape["MemoryLocal"], 13);
        assert_eq!(shape["Global"], 17);
        assert_eq!(shape["RiscvKoalaBearPoseidon2"], 15);
        let unpadded: Vec<(String, usize)> = shape
            .iter()
            .map(|(name, log)| match name.as_str() {
                "RiscvKoalaBearPoseidon2" => (name.clone(), 14),
                _ => (name.clone(), *log),
            })
            .collect();
        assert!(
            !whitelist_shapes().contains(&unpadded),
            "the natural vector is a whitelist shape after all, so the pad is no longer needed"
        );
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
    /// siblings, `ceil(local / LOCAL_MEMORY_DATAPAR)` on MemoryLocal, `2 * local + n + 1` on
    /// Global and `ceil((2 * local + n) / RISCV_POSEIDON2_DATAPAR)` on Poseidon2, for `local` up
    /// to what `n` events can touch. The sweep walks every height boundary and puts the global
    /// event count on each power of two it reaches, where Poseidon2 falls three below Global.
    #[test]
    fn every_precompile_chunk_selects_a_whitelist_shape() {
        use crate::{
            instances::{
                chiptype::riscv_chiptype::RiscvChipType,
                compiler::shapes::riscv_shape::precompile_rows_per_event,
            },
            primitives::consts::{LOCAL_MEMORY_DATAPAR, RISCV_POSEIDON2_DATAPAR},
        };
        let global_rows_cap = 1usize << bucket_log_height("Global", false);
        let local_cap = (1usize << bucket_log_height("MemoryLocal", false)) * LOCAL_MEMORY_DATAPAR;
        let mut power_of_two_counts = 0usize;
        for (kind, _) in RiscvChipType::<Kb>::get_all_precompile_chips()
            .into_iter()
            .filter(|(kind, _)| crate::mle::machine::riscv::air_id_for(kind).is_some())
        {
            let rows_per_event = precompile_rows_per_event(&kind);
            let control = precompile_control_sibling(&kind);
            let mem_per_event = rows_per_event * memory_lookups_per_row(&kind)
                + control.map_or(0, memory_lookups_per_row);
            let n_max = [
                (1usize << bucket_log_height(&kind, false)) / rows_per_event,
                1 << bucket_log_height("SyscallPrecompile", false),
                control.map_or(usize::MAX, |c| 1 << bucket_log_height(c, false)),
            ]
            .into_iter()
            .min()
            .unwrap();
            // Where the syscall's height turns over, and where the kind's does.
            let mut ns = edges(n_max);
            ns.extend(
                (0..usize::BITS)
                    .map(|k| (1usize << k) / rows_per_event)
                    .flat_map(|n| [n, n + 1])
                    .filter(|n| (1..=n_max).contains(n)),
            );
            for n in ns {
                let local_max = (n * mem_per_event)
                    .min(local_cap)
                    .min((global_rows_cap - n - 1) / 2);
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
                        (kind.as_str(), n * rows_per_event),
                        ("SyscallPrecompile", n),
                        ("MemoryLocal", local.div_ceil(LOCAL_MEMORY_DATAPAR)),
                        ("Global", events + 1),
                        (
                            "RiscvKoalaBearPoseidon2",
                            events.div_ceil(RISCV_POSEIDON2_DATAPAR),
                        ),
                    ];
                    natural.extend(control.map(|c| (c, n)));
                    select_deferred(&natural);
                    power_of_two_counts += usize::from(events.is_power_of_two());
                }
            }
        }
        assert!(
            power_of_two_counts > 0,
            "the sweep never put the global event count on a power of two"
        );
    }

    /// Every memory chunk under the caps selects a whitelist shape. MemoryInitialize and
    /// MemoryFinalize take a row per event, Global `init + fin + 1` and Poseidon2
    /// `ceil((init + fin) / RISCV_POSEIDON2_DATAPAR)`; the sweep puts `init + fin` on each power
    /// of two as well as walking each side's boundaries.
    #[test]
    fn every_memory_chunk_selects_a_whitelist_shape() {
        use crate::primitives::consts::RISCV_POSEIDON2_DATAPAR;
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
        let mut power_of_two_counts = 0usize;
        for (init, fin) in pairs {
            let events = init + fin;
            if events == 0 || init > side_cap || fin > side_cap || events + 1 > global_rows_cap {
                continue;
            }
            let mut natural = vec![
                ("Global", events + 1),
                (
                    "RiscvKoalaBearPoseidon2",
                    events.div_ceil(RISCV_POSEIDON2_DATAPAR),
                ),
            ];
            natural.extend((init > 0).then_some(("MemoryInitialize", init)));
            natural.extend((fin > 0).then_some(("MemoryFinalize", fin)));
            select_deferred(&natural);
            power_of_two_counts += usize::from(events.is_power_of_two());
        }
        assert!(
            power_of_two_counts > 0,
            "the sweep never put the event count on a power of two"
        );
    }

    /// The whitelist's size, pinned where no artifact is needed: a shape-table change moves this
    /// literal with it, together with the headroom figures on `MLE_VK_MERKLE_DEPTH`. `vk_map`'s
    /// shipped-artifact test derives the same count from the config and holds the artifact to it.
    #[test]
    fn the_whitelist_shape_count_is_pinned() {
        assert_eq!(mle_riscv_shapes().len(), 15_643, "riscv whitelist shapes");
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

    /// Every ladder row has to prove on a card: TI = sum(interactions x height) over the row's
    /// chips must stay under 2^29, where the GKR size m goes from 29 to 30 and the leaf buffer
    /// outgrows the card. The interaction counts come off a real keygen, so a chip that gains an
    /// interaction moves the rows here rather than at proving time. The third envelope row is the
    /// heaviest, at 0.765 x 2^29.
    #[test]
    fn core_ladder_rows_stay_under_the_gpu_line() {
        use crate::mle::machine::riscv::{
            air_id_for, mle_riscv_air_refs, Engine, RISCV_APP_PREP_AIR_IDS,
        };
        use pico_mle_core::{config::riscv_params_with_100_bits_security, StarkEngine};
        let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(22));
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
        };
        let airs = mle_riscv_air_refs(Arc::new(program), true);
        let (_, vk) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);
        for (r, row) in MLE_CORE_LADDER.iter().enumerate() {
            let ti: u64 = row
                .iter()
                .map(|(name, log)| {
                    let id = air_id_for(name).unwrap_or_else(|| panic!("no air id for {name}"));
                    vk.inner.per_air[id].num_interactions() as u64 * (1u64 << log)
                })
                .sum();
            assert!(
                ti < 1 << 29,
                "core ladder row {r}: TI = {ti} = {:.3} x 2^29 crosses the GPU line",
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

    /// Under the 2^22 memory-event cap a memory chunk's finalize side holds at most 2^22 - 4
    /// events (four buckets) and its initialize side at most the same, so each sits one notch under
    /// Global's ceiling (one row per memory event, plus the padding row).
    #[test]
    fn memory_pair_fits_under_global() {
        let global = bucket_log_height("Global", false);
        assert_eq!(bucket_log_height("MemoryInitialize", false), global - 1);
        assert_eq!(bucket_log_height("MemoryFinalize", false), global - 1);
    }
}
