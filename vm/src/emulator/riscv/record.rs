use super::{
    alu_event_pool::{return_alu_event_buffer, AluEventBuffer},
    cpu_event_pool::{return_cpu_event_buffer, CpuEventBuffer},
    event_types::{RvAddr, RvChunk},
    syscalls::precompiles::{PrecompileEvent, PrecompileEvents, PrecompileLocalMemory},
};
use crate::{
    chips::{
        chips::{
            alu::event::AluEvent,
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_cpu::event::CpuEvent,
            riscv_global::{columns::NUM_GLOBAL_COLS, event::GlobalInteractionEvent},
            riscv_memory::event::{
                MemoryInitializeFinalizeEvent, MemoryLocalEvent, MemoryRecordEnum,
            },
            riscv_poseidon2::{columns::RISCV_NUM_POSEIDON2_COLS, Poseidon2Event},
        },
        gadgets::curves::{
            weierstrass::{bls381::Bls381BaseField, bn254::Bn254BaseField, Bn254, Secp256k1},
            EllipticCurveParameters,
        },
        precompiles::{
            fptower::{
                fp::num_fp_cols, fp2_addsub::num_fp2_addsub_cols, fp2_mul::num_fp2_mul_cols,
            },
            keccak256::columns::NUM_KECCAK_MEM_COLS,
            sha256::{
                compress::columns::NUM_SHA_COMPRESS_COLS, extend::columns::NUM_SHA_EXTEND_COLS,
            },
            uint256::columns::NUM_UINT256_MUL_COLS,
            weierstrass::{
                weierstrass_add::num_weierstrass_add_cols,
                weierstrass_double::num_weierstrass_double_cols,
            },
        },
    },
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::{
        opts::SplitOpts,
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            syscalls::{SyscallCode, SyscallEvent},
        },
    },
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    iter::{PicoBridge, PicoIterator},
    primitives::consts::{KoalaBearConfig, LOCAL_MEMORY_DATAPAR, RISCV_POSEIDON2_DATAPAR},
};
#[cfg(feature = "cuda")]
use cudart::slice::CudaSlice;
use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::{
    env,
    mem::take,
    ops::Range,
    sync::{Arc, OnceLock},
};
use tracing::info;

#[inline(always)]
fn encode_proof_addr_48(addr: u64) -> [u32; 3] {
    assert_eq!(
        addr >> 48,
        0,
        "memory event address 0x{addr:016x} exceeds the frozen 48-bit proof address contract",
    );
    [
        (addr & 0xFFFF) as u32,
        ((addr >> 16) & 0xFFFF) as u32,
        ((addr >> 32) & 0xFFFF) as u32,
    ]
}

/// Tail-merge gate (default ON): pack the deferred memory init/finalize buckets into shared
/// memory-only records (several finalize buckets per record, the initialize buckets riding on
/// the last one). Set `DEFERRED_TAIL_MERGE=0` for the fully legacy split (one standalone
/// deferred-memory record per bucket). Precompile
/// remainders form one record per kind under both settings. Nothing ships with the gate off: the
/// OFF branch was the FRI prover's, whose `fri_commit` could not hold a multi-pair memory record
/// on a 32 GB card, and that proving path left with the tag `legacy-fri-last`. The MLE prover
/// streams its RS commit and proves+verifies the merged records fine.
fn deferred_tail_merge() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("DEFERRED_TAIL_MERGE").map_or(true, |v| v != "0"))
}

/// Merge gate (cached): merge adjacent same-address MemoryLocal entries inside each precompile
/// record ([`merge_precompile_local_mem`]). Default on; `MLE_PRECOMPILE_LOCAL_MEM_MERGE=0` turns
/// it off (A/B and rollback). With the gate off every record is handed to the prover exactly as
/// split produced it.
///
/// The merge changes the MemoryLocal / GcsBind / Poseidon2 heights of precompile records, so a
/// production VK whitelist built before it (or with it off) has to be rebuilt with the same gate
/// setting; the CI setting (`VK_VERIFICATION=false`) is unaffected.
fn precompile_local_mem_merge_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("MLE_PRECOMPILE_LOCAL_MEM_MERGE").map_or(true, |v| v != "0"))
}

/// Tail-merge cells calibration.
///
/// One "full tail block" worth of main-trace cells. Calibrated to the merge-path keccak
/// full block (~2^19 keccak rows at full trace width) that repeated gates proved on a
/// 32 GB card. Per-syscall thresholds derive from it as `TAIL_TARGET_CELLS / cells_per_event`,
/// which reproduces the tuned keccak threshold exactly and lifts the narrow chips
/// (EC/FP/uint256, 330-1711 cols at 1 row/event) whose legacy event-count thresholds sat
/// orders of magnitude below this level (e.g. BN254_DOUBLE at 4096 events = 6.7M cells).
const TAIL_TARGET_CELLS: u64 = 1_575_461_400;

/// Packing budget of a deferred-memory record in *padded* cells: each chip pads its rows to
/// a power of two before stacking, so a memory block costs `mem_tail_padded_cost` (Global plus
/// Poseidon2 area). Calibrated between two measured anchors on a 32 GB card (RTX 5090, MLE
/// prover, streaming RS commit): a 2.14e9-cell tail record proved and verified repeatedly, a
/// 2.52e9-cell one OOM'd (6.4 GB DeviceBuffer allocation while proving). 2.25e9 keeps ~5%
/// above the proven point and ~11% below the failing one. The legacy split
/// (`DEFERRED_TAIL_MERGE=0`) never reaches this path.
///
/// TODO(tail-merge): ALL tail-merge constants in this block (TAIL_TARGET_CELLS, this
/// budget, the row caps below) are calibrated on a 32 GB card only. The legacy per-syscall
/// thresholds were tier-aware (ProverHardwareConfig / PICO_GPU_MEM); under tail-merge a
/// 24 GB tier currently gets the 32 GB-calibrated sizes (e.g. 2^19-row keccak blocks vs
/// the old tier's 2^18). Before enabling DEFERRED_TAIL_MERGE as a default on smaller
/// tiers, either scale these constants per tier or fall back to legacy thresholds there.
const TAIL_MERGE_BUDGET_CELLS: u64 = 2_250_000_000;

/// Maximum deferred memory init+finalize events per tail record. Some prover buffer
/// scales superlinearly with a record's memory volume: an 8.39M-event record (reth-246)
/// tripped a 32 GB (2^35-byte) allocation, while 4.19M-event records proved repeatedly in
/// the earlier gates. Cap at the proven volume; longer streams take further records.
const TAIL_MERGE_MAX_MEM_EVENTS: usize = 1 << 22;

// There is no larger cap: the finalize stream is bucketed on its own
// (`deferred_memory_blocks`) and the init events ride on the last record, so a record under a
// 2^23 cap would hold eight finalize buckets and pad its MemoryFinalize trace to 2^23 -- past the
// whitelist's 22 for that chip (`mle/machine/shape.rs`, `memory_pair_fits_under_global`). Four
// buckets (2^22 - 4 events) is the proven, whitelist-compatible record; longer streams take more
// records of the same shape.

/// Maximum padded rows for a 1-row/event (EC/FP/uint256) tail chip. These chips are
/// interaction-dense (per-limb byte range checks), and the logup/GKR working set scales
/// with interactions × padded height — cells alone do not bound it. 2^17 rows proved
/// in-catch-all (reth-239's SECP256K1_DOUBLE remainder); 2^19 rows OOM'd a 32 GB
/// allocation (reth-246's 373K-event SECP256K1_DOUBLE block).
const TAIL_MERGE_MAX_WIDE_ROWS: usize = 1 << 17;

/// (rows_per_event, trace width) for the precompile chips that appear in deferred tail
/// chunks. Widths come from the chips' column structs at compile time
/// (`size_of::<Cols<u8>>()` — `#[repr(C)]`, all-scalar fields), so AIR width changes
/// (e.g. a column reduction) re-calibrate the tail thresholds automatically.
/// Returns None for syscalls without an entry; callers fall back to the legacy
/// event-count threshold, valued conservatively at one full block per threshold.
pub(crate) fn tail_rows_and_width(syscall_code: SyscallCode) -> Option<(u64, u64)> {
    let (rows, width) = match syscall_code {
        SyscallCode::KECCAK_PERMUTE => (24, NUM_KECCAK_MEM_COLS),
        SyscallCode::SHA_EXTEND => (48, NUM_SHA_EXTEND_COLS),
        SyscallCode::SHA_COMPRESS => (80, NUM_SHA_COMPRESS_COLS),
        SyscallCode::SECP256K1_ADD => (
            1,
            num_weierstrass_add_cols::<<Secp256k1 as EllipticCurveParameters>::BaseField>(),
        ),
        SyscallCode::SECP256K1_DOUBLE => (
            1,
            num_weierstrass_double_cols::<<Secp256k1 as EllipticCurveParameters>::BaseField>(),
        ),
        SyscallCode::BN254_ADD => (
            1,
            num_weierstrass_add_cols::<<Bn254 as EllipticCurveParameters>::BaseField>(),
        ),
        SyscallCode::BN254_DOUBLE => (
            1,
            num_weierstrass_double_cols::<<Bn254 as EllipticCurveParameters>::BaseField>(),
        ),
        SyscallCode::BN254_FP_ADD => (1, num_fp_cols::<Bn254BaseField>()),
        SyscallCode::BN254_FP2_ADD => (1, num_fp2_addsub_cols::<Bn254BaseField>()),
        SyscallCode::BN254_FP2_MUL => (1, num_fp2_mul_cols::<Bn254BaseField>()),
        SyscallCode::BLS12381_FP_ADD => (1, num_fp_cols::<Bls381BaseField>()),
        SyscallCode::BLS12381_FP2_MUL => (1, num_fp2_mul_cols::<Bls381BaseField>()),
        SyscallCode::UINT256_MUL => (1, NUM_UINT256_MUL_COLS),
        _ => return None,
    };
    Some((rows, width as u64))
}

/// Packing cost of a deferred memory block in *padded* cells: one Global row per
/// init/finalize event (padded pow2) plus the Poseidon2 area (one permutation per global
/// event, DATAPAR permutations per row at DATAPAR× width, rows padded pow2). Counting each
/// block's padding separately UNDERSTATES a record that mixes full buckets with a small
/// remainder (pow2 of the parts < pow2 of the sum, up to ~2×); today the
/// TAIL_MERGE_MAX_MEM_EVENTS hard cap bounds the real padded height regardless, so the
/// accounting slack is masked. The old `events / DEFERRED_MEMORY_BUCKET`
/// yardstick badly understated memory items, which is why the fused reth-171 tail OOM'd
/// at a nominally modest budget.
fn mem_tail_padded_cost(events: u64) -> u64 {
    // `+ 1`: the Global trace always carries one trailing padding row.
    let global = (events + 1).next_power_of_two() * NUM_GLOBAL_COLS as u64;
    let poseidon2_rows = events.div_ceil(RISCV_POSEIDON2_DATAPAR as u64);
    let poseidon2 =
        poseidon2_rows.next_power_of_two() * RISCV_NUM_POSEIDON2_COLS::<KoalaBearConfig> as u64;
    global + poseidon2
}

/// Per-record budget on estimated logup-GKR leaves (memory records).
///
/// The MLE prover allocates ONE device buffer for the whole logup-GKR fractional tree,
/// sized `2^(l_skip+n_logup)` Frac elements (32 B each) where
/// `total = Σ_air num_interactions × 2^max(log_height, l_skip)` and the stacked layout
/// pads to the next power of two ≥ `total + 1` (cuda-mle logup_zerocheck/mod.rs,
/// `calculate_n_logup` in mle-core's stacking protocol, verifier-enforced). Crossing the 2^28-leaf
/// step therefore doubles that buffer from 8 GiB to 16 GiB. reth-171's fused keccak tail
/// crossed it (used > 2.68e8 → 16 GiB) and OOM'd once a keccak force-JIT experiment added its
/// lmem residency (that experiment was since rolled back); reth-188's fused tail sits just under it
/// (~2.6e8 by this accounting; measured pad-to-2^28, proved + verified repeatedly).
/// The packer closes a memory record before its estimated leaves reach 2^28: `total` must
/// stay STRICTLY below 2^28 (pad goes to the next pow2 ≥ total+1, so hitting 2^28
/// exactly already doubles the buffer) — hence the `- 1`.
///
/// Like the cells budget above, this is an anchored proxy, not an exact replica of the
/// prover's accounting: per-row interaction counts are hand-derived from the AIRs (see
/// `tail_gkr_interactions`) and shared-chip heights are reconstructed from event counts.
/// The `CHUNK_SPLIT_DEBUG=1` probe prints the estimate per tail record; compare against
/// `G3_MEASURE=1` (cuda-mle) to recalibrate if the tables drift.
const TAIL_MERGE_MAX_GKR_LEAVES: u64 = (1 << 28) - 1;

/// riscv MLE proving lifts every active AIR's height to at least `2^l_skip` in the leaf
/// account; the riscv machine uses `riscv_params_with_100_bits_security` ⇒
/// `DEFAULT_RISCV_L_SKIP = 4` (mle-core/src/config/mod.rs).
const TAIL_GKR_L_SKIP: u32 = 4;

/// Conservative per-row interaction count for tail syscalls without a
/// `tail_gkr_interactions` entry, applied at 1 row/event (matches the
/// `tail_rows_and_width` fallback discipline: value unknown chips high so they close
/// records early rather than sneak a record over the pow2 step). It has to sit above the widest
/// AIR in the machine, which is what `interaction_counts_match_their_airs` asserts -- the widest
/// measures 1843/row today, so only the bound is pinned, not which AIR it is.
const TAIL_GKR_FALLBACK_INTERACTIONS: u64 = 2048;

/// Per-row interaction counts of the record-shared chips that every deferred record
/// activates alongside the precompile chips. Counted from the AIR eval code — one
/// `looking_*`/`looked_*` call = one interaction instance, loops multiplied out; counts
/// are structural per row, independent of multiplicities. Sources (current tree):
///   - Global 8/row: 1 looked Global (riscv_global/constraints.rs:46) + 1 looking
///     Poseidon2 (gadgets/global_interaction.rs) + 6 byte-bus range instances
///     (global_interaction.rs:131-240). Six, not eight: the `kind < 32` LTU is gone (every
///     sender passes a compile-time constant, so the multiset already pins the receiver's
///     column) and two U8 checks share one instance.
///   - MemoryInit/Finalize 13/row: 10 × U16 (initialize_finalize/constraints.rs:43-45) +
///     1 U8 pair (:55) + 1 looking Global (:70/:90) + 1 U16 inside LtWordU16Gadget
///     (gadgets/lt_word_u16.rs:190).
///   - MemoryLocal 44/row: 11 per event slot (local/constraints.rs, the per-entry loop: two
///     Global, two Memory-bus, the gated chunk-gap U16, the two limbs of the in-chunk clk-gap
///     check, two u8 pairs and two u16 limbs of the initial value) × LOCAL_MEMORY_DATAPAR(4)
///     slots/row.
///   - Poseidon2 4/row: 1 looked (riscv_poseidon2/constraints.rs:79) ×
///     RISCV_POSEIDON2_DATAPAR(4) slots/row.
///   - Syscall 4/row: U8(syscall_id) + U16(arg1[0]) (syscall/constraints.rs:27,29) +
///     looked/looking syscall (:51/:85) + looking Global (:62/:96).
///   - Byte 10/row × 2^17 fixed rows (byte/constraints.rs:33-63, byte/traces.rs:29).
///   - Program 1/row (riscv_program/constraints.rs:41) × pow2(instruction count) rows.
const TAIL_GKR_GLOBAL_INTERACTIONS: u64 = 8;
const TAIL_GKR_INIT_FIN_INTERACTIONS: u64 = 13;
const TAIL_GKR_MEMORY_LOCAL_INTERACTIONS: u64 = 11 * LOCAL_MEMORY_DATAPAR as u64;
const TAIL_GKR_POSEIDON2_INTERACTIONS: u64 = RISCV_POSEIDON2_DATAPAR as u64;
const TAIL_GKR_SYSCALL_INTERACTIONS: u64 = 4;
const TAIL_GKR_BYTE_LEAVES: u64 = 10 * (1 << 17);

/// Per-row interaction count of each tail precompile chip's AIR. Same key set as
/// `tail_rows_and_width` — extend BOTH when admitting a new syscall to the tail tables.
///
/// Chips whose activation is driven by CPU execution rather than by precompile events are
/// deliberately absent, because a deferred record cannot activate them: `split` builds every
/// deferred record with only `precompile_events` populated, leaving `cpu_events` empty, and
/// `EcallChip`/`CpuChip`/`MemoryReadWriteChip`/`SyscallChip::riscv`/the ALU chips all gate
/// `is_active` on `cpu_events`. Their omission is correct, not an oversight.
/// Counted from the chips' AIR eval code (see `TAIL_GKR_GLOBAL_INTERACTIONS` note on
/// method). Unlike the widths (size_of-derived), these constants do NOT track AIR
/// changes automatically: re-count when a chip's lookups change. They only steer
/// packing, never soundness.
///
/// Each entry carries `+ 3n`, where `n` is the number of `SyscallAddrGadget` fields **in the
/// AIR this entry is measured against** (the gadget range-checks its three address limbs).
/// A gadget living in a sibling controller AIR does not count — see SHA_EXTEND/SHA_COMPRESS. Under-counting is what lets a
/// tail record cross the leaf budget and double the logup-GKR device buffer.
///   - KECCAK_PERMUTE 280 = 277 + 3×1: SyscallAddr 1 + 25×AddrAdd 3 + 25×mem-access 4 +
///     looked_syscall 1 + 25×u16-range 4 (precompiles/keccak256/control.rs -- unlike the SHA
///     entries below, this one counts the sibling controller AIR, which is where the permute
///     chip's syscall and memory rows live);
///     mem-access = 2 Memory bus + 2 byte-bus u25 range (builder/riscv_memory.rs:46-235).
///   - SHA_EXTEND 81 and SHA_COMPRESS 99 take **no** `+ 3n`: both chips keep their
///     `SyscallAddrGadget` in a separate controller AIR, which this table does not count.
///     SHA_EXTEND 81 = 3 + 5×AddrAdd 3 + 5×mem 4 + 6×rot/shift 4 + 4×xor 4 + add4 3
///     (precompiles/sha256/extend/constraints.rs); the chip's *constraint* count happens to
///     be 61, which is what this entry held before that.
///     SHA_COMPRESS 99 = 3 + (mem 4 + 3×AddrAdd 3) + (6×rot 4 + 7×xor 4 + 5×and 4 +
///     add5 3 + 3×add 2) + add 2 (precompiles/sha256/compress/constraints.rs).
///   - Weierstrass add 1127 = 1121 + 3×2 (secp256k1 = bn254: 32 limbs, 62 witness,
///     8 words/point, add = 22·WCP + 10·(L+W) + 5).
///     **Double is 1223, not 1126 + 3×1** — its AIR gained far more than the address gadget in
///     the upstream chip-completeness work, so the old closed form no longer predicts it.
///     Take the measured number; the test below is what pins it
///     (precompiles/weierstrass/weierstrass_{add,double}.rs).
///   - Fp/Fp2, all 3×2 (bn254: L=32 W=62 WFE=4 WCP=8; bls381: L=48 W=94 WFE=6 WCP=12):
///     fp = 22·WFE + (L+W) + 4 ⇒ 192 / 284; fp2 addsub = 22·WCP + 2·(L+W) + 5 ⇒ 375;
///     fp2 mul = 22·WCP + 6·(L+W) + 5 ⇒ 751 / 1127 (precompiles/fptower/*.rs).
///   - UINT256_MUL 237 = 231 + 3×2, 231 = 33·WFE + (L+W=95) + 4
///     (precompiles/uint256/constraints.rs).
///
/// `interaction_counts_match_their_airs` below asserts all of this against real keygen —
/// it is the arbiter, not this comment.
fn tail_gkr_interactions(syscall_code: SyscallCode) -> Option<u64> {
    Some(match syscall_code {
        SyscallCode::KECCAK_PERMUTE => 280,
        SyscallCode::SHA_EXTEND => 81,
        SyscallCode::SHA_COMPRESS => 99,
        SyscallCode::SECP256K1_ADD | SyscallCode::BN254_ADD => 1127,
        SyscallCode::SECP256K1_DOUBLE | SyscallCode::BN254_DOUBLE => 1223,
        SyscallCode::BN254_FP_ADD => 192,
        SyscallCode::BN254_FP2_ADD => 375,
        SyscallCode::BN254_FP2_MUL => 751,
        SyscallCode::BLS12381_FP_ADD => 284,
        SyscallCode::BLS12381_FP2_MUL => 1127,
        SyscallCode::UINT256_MUL => 237,
        _ => return None,
    })
}

/// Running GKR-leaf account of the tail record being packed. Per-syscall main
/// chips are unique per record, so their pow2 padding is exact per item; the
/// record-shared chips (Global/Poseidon2/MemoryLocal/InitFin/Syscall) are re-padded
/// from running event totals on every probe, exactly like tracegen will size them:
///   - 1 local-memory event → 2 global events (`riscv_memory/local/traces.rs`),
///   - 1 memory init/finalize event → 1 global event (initialize_finalize/traces.rs:247),
///   - 1 syscall (= precompile) event → 1 global event (syscall/traces.rs:140),
///   - 1 global event → 1 Poseidon2 permutation (`riscv_global/traces.rs`).
///
/// Byte and Program are height-invariant per record and enter as `base_leaves`
/// (both are always active in a deferred record: byte/traces.rs:92,
/// riscv_program/traces.rs:191).
#[derive(Clone, Copy)]
struct TailGkrLeavesAccount {
    base_leaves: u64,
    precompile_leaves: u64,
    local_mem_events: u64,
    precompile_events: u64,
    init_events: u64,
    finalize_events: u64,
}

impl TailGkrLeavesAccount {
    fn new(program_instructions: u64) -> Self {
        Self {
            base_leaves: TAIL_GKR_BYTE_LEAVES + Self::lift(program_instructions),
            precompile_leaves: 0,
            local_mem_events: 0,
            precompile_events: 0,
            init_events: 0,
            finalize_events: 0,
        }
    }

    /// pow2-padded, l_skip-lifted height of an active chip (0 rows = inactive chip).
    fn lift(rows: u64) -> u64 {
        if rows == 0 {
            0
        } else {
            rows.next_power_of_two().max(1 << TAIL_GKR_L_SKIP)
        }
    }

    fn add_precompile(&mut self, syscall_code: SyscallCode, events: u64, local_mem_events: u64) {
        let main = match (
            tail_gkr_interactions(syscall_code),
            tail_rows_and_width(syscall_code),
        ) {
            (Some(interactions), Some((rows_per_event, _))) => {
                interactions.saturating_mul(Self::lift(events.saturating_mul(rows_per_event)))
            }
            _ => TAIL_GKR_FALLBACK_INTERACTIONS.saturating_mul(Self::lift(events)),
        };
        self.precompile_leaves = self.precompile_leaves.saturating_add(main);
        self.local_mem_events += local_mem_events;
        self.precompile_events += events;
    }

    fn add_memory(&mut self, init_events: u64, finalize_events: u64) {
        self.init_events += init_events;
        self.finalize_events += finalize_events;
    }

    fn total_leaves(&self) -> u64 {
        // `2 * local_mem_events` over-counts (a fresh entry raises one Global event, not two);
        // the estimate stays on the conservative side of the line.
        let global_rows = 2 * self.local_mem_events
            + self.init_events
            + self.finalize_events
            + self.precompile_events;
        // `+ 1`: the Global trace always carries one trailing padding row (as in
        // `mem_tail_padded_cost`), so a power-of-two event count lifts to the next power.
        let global = TAIL_GKR_GLOBAL_INTERACTIONS * Self::lift(global_rows + 1);
        let poseidon2 = TAIL_GKR_POSEIDON2_INTERACTIONS
            * Self::lift(global_rows.div_ceil(RISCV_POSEIDON2_DATAPAR as u64));
        let memory_local = TAIL_GKR_MEMORY_LOCAL_INTERACTIONS
            * Self::lift(self.local_mem_events.div_ceil(LOCAL_MEMORY_DATAPAR as u64));
        let init_fin = TAIL_GKR_INIT_FIN_INTERACTIONS
            * (Self::lift(self.init_events) + Self::lift(self.finalize_events));
        let syscall = TAIL_GKR_SYSCALL_INTERACTIONS * Self::lift(self.precompile_events);
        self.base_leaves
            .saturating_add(self.precompile_leaves)
            .saturating_add(global)
            .saturating_add(poseidon2)
            .saturating_add(memory_local)
            .saturating_add(init_fin)
            .saturating_add(syscall)
    }
}

pub const THRESHOLD_2POW10: usize = 1 << 10;
pub const THRESHOLD_2POW12: usize = 1 << 12;
pub const THRESHOLD_2POW14: usize = 1 << 14;
pub const THRESHOLD_2POW15: usize = 1 << 15;
pub const THRESHOLD_2POW16: usize = 1 << 16;
pub const THRESHOLD_2POW17: usize = 1 << 17;
pub const THRESHOLD_2POW18: usize = 1 << 18;
pub const THRESHOLD_2POW19: usize = 1 << 19;
pub const THRESHOLD_2POW20: usize = 1 << 20;
pub const THRESHOLD_2POW21: usize = 1 << 21;

/// pow2-aware packing of the deferred memory-init/finalize chunk.
///
/// The Global chip's height for a deferred (memory) record is
/// `memory_initialize_events.len() + memory_finalize_events.len()` (one global
/// interaction event per init and per finalize event; see the Initialize/Finalize
/// trace event counter) **plus one trailing padding row** that the accumulation
/// constraints require (`riscv_global/traces.rs`), padded up to the next power of two;
/// the Poseidon2 chip follows (~1 perm per global event).
///
/// The previous bucket size (`opts.memory * 2` ≈ 67M) packed every init/finalize
/// event into a single deferred record, so e.g. reth-188's 2.55M global events
/// padded to 2^22 = 4,194,304 rows (wasting ~1.65M rows on Global + the matching
/// Poseidon2 rows). Bucketing each of the (separately address-sorted) finalize and
/// init streams into fixed-size buckets makes a "full" bucket pad-free, and only the
/// trailing record pads (e.g. 2.55M finalize -> [two full buckets] + [~452K -> 2^19]).
///
/// The size is one under 2^20 because of that padding row: with 2^20-event buckets four
/// full buckets would be exactly 2^22 events, which the cap check in `split` refuses (the
/// row would push the Global trace to 2^23), so four buckets could not share a record. At
/// 2^20 - 1 four full buckets are 2^22 - 4 events (Global exactly 2^22, the volume the
/// tail-merge caps were proven at), and the init/finalize traces still pad to the same
/// 2^20 they did before.
///
/// Address chaining across records is unchanged: init and finalize are still
/// consumed in sorted order as contiguous slices, and each record's
/// `last_*_addr_limbs` feeds the next record's `previous_*_addr_limbs`
/// (see `split`), which holds for any bucket size.
pub const DEFERRED_MEMORY_BUCKET: usize = (1 << 20) - 1;

/// The blocks the deferred memory stream is packed in, as `(init, finalize)` index ranges into
/// the address-sorted event vectors: every finalize bucket (`DEFERRED_MEMORY_BUCKET` events,
/// the last one shorter) on its own, then the initialize stream in buckets of the same size.
///
/// Finalize goes first because it is the bulk of the stream (one event per touched word, while
/// the initialize stream holds the registers and the nonzero hint-written words only), and
/// the init buckets last so that MemoryInitialize rows live in the trailing memory record(s)
/// and every record before them keeps a frozen init cursor (`split`). Bucketing the init stream
/// too keeps a MemoryInitialize trace under the 2^22 cap however many hint words a block has.
fn deferred_memory_blocks(
    init_events: usize,
    finalize_events: usize,
) -> Vec<(Range<usize>, Range<usize>)> {
    let mut blocks: Vec<(Range<usize>, Range<usize>)> = (0..finalize_events)
        .step_by(DEFERRED_MEMORY_BUCKET)
        .map(|start| {
            (
                0..0,
                start..(start + DEFERRED_MEMORY_BUCKET).min(finalize_events),
            )
        })
        .collect();
    blocks.extend(
        (0..init_events)
            .step_by(DEFERRED_MEMORY_BUCKET)
            .map(|start| {
                (
                    start..(start + DEFERRED_MEMORY_BUCKET).min(init_events),
                    finalize_events..finalize_events,
                )
            }),
    );
    blocks
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuMemoryTier {
    Tier24GB,
    Tier32GB,
}

pub struct ProverHardwareConfig {
    tier: GpuMemoryTier,
}

impl ProverHardwareConfig {
    /// Returns the recommended hard limit for a specific syscall
    /// based on the active hardware tier.
    pub fn get_threshold(&self, syscall: SyscallCode) -> usize {
        match self.tier {
            GpuMemoryTier::Tier24GB => self.threshold_24gb(syscall),
            GpuMemoryTier::Tier32GB => self.threshold_32gb(syscall),
        }
    }

    // --- Internal Threshold Logic ---
    // TODO: double-check & testing here to optimize the parameters
    // TODO: MemoryInit/Finalize Split Threshold
    fn threshold_32gb(&self, syscall: SyscallCode) -> usize {
        match syscall {
            SyscallCode::KECCAK_PERMUTE => THRESHOLD_2POW18 / 24,
            SyscallCode::SHA_EXTEND => THRESHOLD_2POW20 / 48,
            SyscallCode::SHA_COMPRESS => THRESHOLD_2POW20 / 80,

            SyscallCode::SECP256K1_ADD => THRESHOLD_2POW15,
            SyscallCode::SECP256K1_DOUBLE => THRESHOLD_2POW16,
            SyscallCode::SECP256K1_FP_ADD => THRESHOLD_2POW16,

            SyscallCode::SECP256R1_ADD => THRESHOLD_2POW15,
            SyscallCode::SECP256R1_DOUBLE => THRESHOLD_2POW16,

            SyscallCode::BLS12381_FP_ADD
            | SyscallCode::POSEIDON2_PERMUTE
            | SyscallCode::UINT256_MUL
            | SyscallCode::BN254_FP_ADD => THRESHOLD_2POW15,

            SyscallCode::BLS12381_FP2_MUL
            | SyscallCode::BN254_FP2_MUL
            | SyscallCode::BLS12381_FP2_ADD
            | SyscallCode::BN254_FP2_ADD => THRESHOLD_2POW14,

            _ => THRESHOLD_2POW12,
        }
    }

    fn threshold_24gb(&self, syscall: SyscallCode) -> usize {
        match syscall {
            SyscallCode::KECCAK_PERMUTE => THRESHOLD_2POW17 / 24,
            SyscallCode::SHA_EXTEND => THRESHOLD_2POW19 / 48,
            SyscallCode::SHA_COMPRESS => THRESHOLD_2POW19 / 80,
            SyscallCode::BLS12381_FP_ADD => THRESHOLD_2POW15,
            SyscallCode::POSEIDON2_PERMUTE => THRESHOLD_2POW15,
            SyscallCode::BLS12381_ADD => THRESHOLD_2POW12,
            SyscallCode::BLS12381_FP2_MUL => THRESHOLD_2POW14,
            SyscallCode::BN254_FP2_MUL => THRESHOLD_2POW14,
            SyscallCode::ED_DECOMPRESS => THRESHOLD_2POW12,
            SyscallCode::UINT256_MUL => THRESHOLD_2POW15,
            SyscallCode::BLS12381_DOUBLE => THRESHOLD_2POW12,
            SyscallCode::BN254_DOUBLE => THRESHOLD_2POW12,
            SyscallCode::BLS12381_DECOMPRESS => THRESHOLD_2POW12,
            SyscallCode::SECP256K1_DECOMPRESS => THRESHOLD_2POW12,
            SyscallCode::SECP256R1_DECOMPRESS => THRESHOLD_2POW12,
            SyscallCode::ED_ADD => THRESHOLD_2POW12,
            SyscallCode::BN254_ADD => THRESHOLD_2POW12,
            SyscallCode::SECP256K1_FP_ADD => THRESHOLD_2POW16,
            SyscallCode::BN254_FP_ADD => THRESHOLD_2POW15,
            SyscallCode::SECP256K1_ADD => THRESHOLD_2POW14,
            SyscallCode::SECP256R1_ADD => THRESHOLD_2POW14,
            SyscallCode::BLS12381_FP2_ADD => THRESHOLD_2POW14,
            SyscallCode::BN254_FP2_ADD => THRESHOLD_2POW14,
            SyscallCode::SECP256K1_DOUBLE => THRESHOLD_2POW15,
            SyscallCode::SECP256R1_DOUBLE => THRESHOLD_2POW15,
            _ => THRESHOLD_2POW12,
        }
    }
}

static PROVER_HARDWARE_CONFIG: OnceLock<ProverHardwareConfig> = OnceLock::new();

/// The tier `PICO_GPU_MEM` names, if set: `5090`, `32gb` or `high` is the 32 GB tier, anything
/// else the 24 GB one.
pub fn gpu_memory_tier_from_env() -> Option<GpuMemoryTier> {
    let value = env::var("PICO_GPU_MEM").ok()?.to_lowercase();
    Some(match value.as_str() {
        "5090" | "32gb" | "high" => GpuMemoryTier::Tier32GB,
        _ => GpuMemoryTier::Tier24GB,
    })
}

/// [`init_prover_hardware_config`] found the config already latched to another tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "the prover hardware config is already latched to {latched:?}, not {requested:?}: an earlier \
     emulation in this process read it first (set PICO_GPU_MEM to pin it)"
)]
pub struct TierAlreadySet {
    pub latched: GpuMemoryTier,
    pub requested: GpuMemoryTier,
}

/// Latch `tier` for the rest of the process. The config is read by every emulation's record split
/// and latched on first use, so a GPU prover calls this before its first emulation. Ok if the
/// config already holds `tier`.
pub fn init_prover_hardware_config(tier: GpuMemoryTier) -> Result<(), TierAlreadySet> {
    let latched = PROVER_HARDWARE_CONFIG
        .get_or_init(|| ProverHardwareConfig::logged(tier))
        .tier;
    if latched == tier {
        Ok(())
    } else {
        Err(TierAlreadySet {
            latched,
            requested: tier,
        })
    }
}

/// The process's hardware config; latched on first use from `PICO_GPU_MEM` unless
/// [`init_prover_hardware_config`] ran first.
pub fn get_prover_hardware_config() -> &'static ProverHardwareConfig {
    PROVER_HARDWARE_CONFIG.get_or_init(|| {
        // Unset means the 32 GB tier, the one the release is calibrated on; the CPU build has no
        // card to size for and keeps that default too.
        ProverHardwareConfig::logged(gpu_memory_tier_from_env().unwrap_or(GpuMemoryTier::Tier32GB))
    })
}

impl ProverHardwareConfig {
    pub fn tier(&self) -> GpuMemoryTier {
        self.tier
    }

    fn logged(tier: GpuMemoryTier) -> Self {
        let config = ProverHardwareConfig { tier };

        info!(
            tier = ?config.tier,

            // --- Hashing & Permutation ---
            keccak_permute = config.get_threshold(SyscallCode::KECCAK_PERMUTE),
            sha_extend     = config.get_threshold(SyscallCode::SHA_EXTEND),
            sha_compress   = config.get_threshold(SyscallCode::SHA_COMPRESS),
            poseidon2      = config.get_threshold(SyscallCode::POSEIDON2_PERMUTE),

            // --- SECP256K1 Operations ---
            secp_add        = config.get_threshold(SyscallCode::SECP256K1_ADD),
            secp_double     = config.get_threshold(SyscallCode::SECP256K1_DOUBLE),
            secp_fp_add     = config.get_threshold(SyscallCode::SECP256K1_FP_ADD),
            secp_decompress = config.get_threshold(SyscallCode::SECP256K1_DECOMPRESS),

            // --- SECP256R1 Operations ---
            secp_add        = config.get_threshold(SyscallCode::SECP256R1_ADD),
            secp_double     = config.get_threshold(SyscallCode::SECP256R1_DOUBLE),
            secp_decompress = config.get_threshold(SyscallCode::SECP256R1_DECOMPRESS),

            // --- BN254 Operations ---
            bn254_add     = config.get_threshold(SyscallCode::BN254_ADD),
            bn254_double  = config.get_threshold(SyscallCode::BN254_DOUBLE),
            bn254_fp_add  = config.get_threshold(SyscallCode::BN254_FP_ADD),
            bn254_fp2_add = config.get_threshold(SyscallCode::BN254_FP2_ADD),
            bn254_fp2_mul = config.get_threshold(SyscallCode::BN254_FP2_MUL),

            // --- BLS12381 Operations ---
            bls_add        = config.get_threshold(SyscallCode::BLS12381_ADD),
            bls_double     = config.get_threshold(SyscallCode::BLS12381_DOUBLE),
            bls_fp_add     = config.get_threshold(SyscallCode::BLS12381_FP_ADD),
            bls_fp2_add    = config.get_threshold(SyscallCode::BLS12381_FP2_ADD),
            bls_fp2_mul    = config.get_threshold(SyscallCode::BLS12381_FP2_MUL),
            bls_decompress = config.get_threshold(SyscallCode::BLS12381_DECOMPRESS),

            // --- Edwards & Others ---
            ed_add        = config.get_threshold(SyscallCode::ED_ADD),
            ed_decompress = config.get_threshold(SyscallCode::ED_DECOMPRESS),
            uint256_mul   = config.get_threshold(SyscallCode::UINT256_MUL),

            "Initialized Pico GPU Prover Config"
        );

        config
    }
}

/// A record of the emulation of a program.
///
/// The trace of the emulation is represented as a list of "events" that occur every cycle.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct EmulationRecord {
    /// The program.
    pub program: Arc<Program>,

    /// CPU events stored in a pinned memory buffer for fast CPU writing and host->device transfer
    #[serde(default)]
    pub cpu_events: CpuEventBuffer,

    pub memory_read_write_event_indices: Vec<usize>,

    /// A trace of the ADD, ADDI, and SUB events (pinned memory for fast H2D transfer).
    #[serde(default)]
    pub add_sub_events: AluEventBuffer,
    /// A trace of the MUL events.
    pub mul_events: Vec<AluEvent>,
    /// A trace of the XOR, XORI, OR, ORI, AND, and ANDI events.
    pub bitwise_events: Vec<AluEvent>,
    /// A trace of the SLL and SLLI events.
    pub shift_left_events: Vec<AluEvent>,
    /// A trace of the SRL, SRLI, SRA, and SRAI events.
    pub shift_right_events: Vec<AluEvent>,
    /// A trace of the DIV, DIVU, REM, and REMU events.
    pub divrem_events: Vec<AluEvent>,
    /// A trace of the SLT, SLTI, SLTU, and SLTIU events (pinned memory for fast H2D transfer).
    #[serde(default)]
    pub lt_events: AluEventBuffer,
    /// A trace of the byte lookups that are needed.
    pub byte_lookups: HashMap<ByteLookupEvent, usize>,
    /// A trace of the memory initialize events.
    pub memory_initialize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of the memory finalize events.
    pub memory_finalize_events: Vec<MemoryInitializeFinalizeEvent>,
    /// A trace of all the chunk's local memory events.
    pub cpu_local_memory_access: Vec<MemoryLocalEvent>,
    /// Public values
    pub public_values: PublicValues<u32, u32>,
    /// Whether this record represents the main CPU chunk.
    pub is_cpu_chunk: bool,
    /// A trace of the precompile events.
    pub precompile_events: PrecompileEvents,
    /// A trace of all the syscall events.
    pub syscall_events: Vec<SyscallEvent>,
    /// A trace of all the global interaction events.
    pub poseidon2_events: Vec<Poseidon2Event>,
    /// A trace of all the global interaction events.
    pub global_lookup_events: Vec<GlobalInteractionEvent>,
    /// The shape of the proof.
    pub shape: Option<RiscvPadShape>,
    /// Last record flag.
    pub is_last: bool,
}

impl EmulationRecord {
    #[must_use]
    pub fn new(program: Arc<Program>) -> Self {
        // Since we defined a custom `Drop` for EmulationRecord, we need to initialize each field.
        Self {
            program,
            cpu_events: CpuEventBuffer::empty(),
            memory_read_write_event_indices: Vec::new(),
            add_sub_events: AluEventBuffer::empty(),
            mul_events: Vec::new(),
            bitwise_events: Vec::new(),
            shift_left_events: Vec::new(),
            shift_right_events: Vec::new(),
            divrem_events: Vec::new(),
            lt_events: AluEventBuffer::empty(),
            byte_lookups: HashMap::new(),
            memory_initialize_events: Vec::new(),
            memory_finalize_events: Vec::new(),
            cpu_local_memory_access: Vec::new(),
            public_values: PublicValues::default(),
            is_cpu_chunk: true,
            precompile_events: PrecompileEvents::default(),
            syscall_events: Vec::new(),
            poseidon2_events: Vec::new(),
            global_lookup_events: Vec::new(),
            shape: None,
            is_last: false,
        }
    }

    /// Efficiently adds multiple CPU events to the buffer from a slice.
    ///
    /// It adds as many events as can fit in the buffer's remaining capacity.
    /// If the buffer is a `Empty`, it will acquire a real buffer from the pool.
    ///
    /// Returns the number of events that were successfully added.
    pub fn add_cpu_events(&mut self, events: &[CpuEvent]) -> Result<usize, &'static str> {
        if events.is_empty() {
            return Ok(0);
        }

        // Ensure we have a real buffer before computing capacity.
        if matches!(self.cpu_events, CpuEventBuffer::Empty) {
            if let Some(buf) = super::cpu_event_pool::get_cpu_event_buffer() {
                self.cpu_events = buf;
            } else {
                // Pool exhausted; cannot add any events now.
                return Ok(0);
            }
        }

        let remaining_cap = self.cpu_events.remaining_capacity();
        let num_to_add = events.len().min(remaining_cap);

        if num_to_add > 0 {
            self.cpu_events.extend_from_slice(&events[..num_to_add])?;
        }

        Ok(num_to_add)
    }

    /// Clears all CPU events in the buffer.
    pub fn clear_cpu_events(&mut self) {
        self.cpu_events.clear();
    }

    /// Add a mul event to the execution record.
    pub fn add_mul_event(&mut self, mul_event: AluEvent) {
        self.mul_events.push(mul_event);
    }

    /// Add a lt event to the execution record.
    pub fn add_lt_event(&mut self, lt_event: AluEvent) {
        let _ = self.lt_events.push_alu(lt_event);
    }

    /// Add a batch of alu events to the execution record.
    pub fn add_alu_events(&mut self, mut alu_events: HashMap<Opcode, Vec<AluEvent>>) {
        for (opcode, value) in &mut alu_events {
            match opcode {
                Opcode::ADD | Opcode::ADDW | Opcode::SUB | Opcode::SUBW => {
                    let _ = self.add_sub_events.append_vec(value);
                }
                Opcode::MUL | Opcode::MULH | Opcode::MULHU | Opcode::MULHSU | Opcode::MULW => {
                    self.mul_events.append(value);
                }
                Opcode::XOR | Opcode::OR | Opcode::AND => {
                    self.bitwise_events.append(value);
                }
                Opcode::SLL | Opcode::SLLW => {
                    self.shift_left_events.append(value);
                }
                Opcode::SRL | Opcode::SRA | Opcode::SRLW | Opcode::SRAW => {
                    self.shift_right_events.append(value);
                }
                Opcode::SLT | Opcode::SLTU => {
                    let _ = self.lt_events.append_vec(value);
                }
                Opcode::DIV
                | Opcode::DIVU
                | Opcode::REM
                | Opcode::REMU
                | Opcode::DIVW
                | Opcode::DIVUW
                | Opcode::REMW
                | Opcode::REMUW => {
                    self.divrem_events.append(value);
                }
                _ => {
                    panic!("Invalid opcode: {opcode:?}");
                }
            }
        }
    }

    #[inline]
    /// Add a precompile event to the execution record.
    pub fn add_precompile_event(
        &mut self,
        syscall_code: SyscallCode,
        syscall_event: SyscallEvent,
        event: PrecompileEvent,
    ) {
        self.precompile_events
            .add_event(syscall_code, syscall_event, event);
    }

    /// Get all the precompile events for a syscall code.
    #[inline]
    #[must_use]
    pub fn get_precompile_events(
        &self,
        syscall_code: SyscallCode,
    ) -> &Vec<(SyscallEvent, PrecompileEvent)> {
        self.precompile_events
            .get_events(syscall_code)
            .expect("Precompile events not found")
    }

    /// Get all the local memory events.
    #[inline]
    pub fn get_local_mem_events(&self) -> impl Iterator<Item = &MemoryLocalEvent> {
        let precompile_local_mem_events = self.precompile_events.get_local_mem_events();
        precompile_local_mem_events.chain(self.cpu_local_memory_access.iter())
    }

    /// Return the number of rows needed for a chip, according to the proof shape specified in the
    /// struct.
    pub fn shape_chip_size(&self, chip_name: &str) -> Option<usize> {
        self.shape
            .as_ref()
            .map(|shape| {
                shape.inner.get(chip_name).unwrap_or_else(|| {
                    panic!(
                        "Chip {} not found in specified shape, full shape: {:?}, ",
                        chip_name, self.shape
                    )
                })
            })
            .copied()
    }

    /// Take out events from the [`EmulationRecord`] that should be deferred to a separate chunk.
    ///
    /// Note: we usually defer events that would increase the recursion cost significantly if
    /// included in every chunk.
    #[must_use]
    pub fn defer(&mut self) -> EmulationRecord {
        let mut emulation_record = EmulationRecord::new(self.program.clone());
        emulation_record.is_cpu_chunk = false;
        // Note: CPU event buffers are not shared in defer operations
        // Each new record will need to acquire its own buffer if needed
        emulation_record.precompile_events = take(&mut self.precompile_events);
        // emulation_record.uint256_mul_events = take(&mut self.uint256_mul_events);
        emulation_record.memory_initialize_events = take(&mut self.memory_initialize_events);
        emulation_record.memory_finalize_events = take(&mut self.memory_finalize_events);
        emulation_record
    }

    /// Splits the deferred [`EmulationRecord`] into multiple [`EmulationRecord`]s, each which
    /// contain a "reasonable" number of deferred events.
    ///
    /// Per syscall, full threshold-sized groups become standalone records, and the per-syscall
    /// remainder becomes one more record of that kind alone. The deferred memory buckets are
    /// packed into memory-only records (tail-merge). Order: full blocks (sorted) → one record
    /// per remainder → deferred-memory records.
    ///
    /// # Arguments
    /// * `last` - Whether this is the last record in emulation (triggers MemoryInit/Finalize processing)
    /// * `opts` - Split options containing thresholds
    /// * `committed_batch_idx` - The current batch_idx that sequencer has processed.
    ///   Only events with `chunk <= committed_batch_idx + 1` are considered.
    ///   Use `u32::MAX` to disable filtering (legacy behavior).
    pub fn split(
        &mut self,
        last: bool,
        opts: SplitOpts,
        committed_batch_idx: u32,
    ) -> Vec<EmulationRecord> {
        let hardware_config = get_prover_hardware_config();

        // committed_chunk matches SyscallEvent.chunk semantics (= batch_idx + 1)
        // Use saturating_add to handle u32::MAX case (disable filtering)
        let committed_chunk = committed_batch_idx.saturating_add(1);
        let program = self.program.clone();

        // Per-syscall: full threshold-sized groups become standalone records; the per-syscall
        // remainder (< threshold events) is handed back separately and becomes its own record
        // below, after all full blocks.
        //
        // Under tail-merge, full-block thresholds are calibrated per chip class, every
        // bound anchored to a gate-proven scale (the legacy path, gate off, is untouched):
        //   - KECCAK: cells-derived (TAIL_TARGET_CELLS / cells_per_event ⇒ its proven
        //     2^19-row block). Keccak is wide but interaction-light.
        //   - SHA extend/compress: keep the legacy thresholds (proven 2^20-row blocks);
        //     cells-derivation would over-raise them by an order of magnitude.
        //   - 1-row/event EC/FP/uint256 chips: cells-derived but capped at
        //     TAIL_MERGE_MAX_WIDE_ROWS — they are interaction-dense and the GKR working
        //     set scales with interactions × padded height, which cells alone do not
        //     bound (2^17 rows proven, 2^19 OOM'd — see the constant).
        //   - Syscalls without a cells entry keep the hardware-tier threshold.
        let effective_threshold = |syscall_code: SyscallCode| {
            let legacy = hardware_config.get_threshold(syscall_code);
            if !deferred_tail_merge() {
                return legacy;
            }
            match tail_rows_and_width(syscall_code) {
                Some((rows_per_event, width)) => {
                    let cells_derived =
                        (TAIL_TARGET_CELLS / (rows_per_event * width).max(1)) as usize;
                    match syscall_code {
                        // Clamp to the proven 2^19-row block: cells-derivation lands 8 rows
                        // under the pow2 cliff today (21845×24 = 524,280), and any future
                        // keccak column reduction would push it over — doubling the padded
                        // block past the measured OOM anchor without tripping any cap.
                        SyscallCode::KECCAK_PERMUTE => {
                            cells_derived.min((1usize << 19) / rows_per_event as usize)
                        }
                        SyscallCode::SHA_EXTEND | SyscallCode::SHA_COMPRESS => legacy,
                        _ => cells_derived
                            .min(TAIL_MERGE_MAX_WIDE_ROWS / (rows_per_event as usize).max(1)),
                    }
                }
                None => legacy,
            }
        };
        let per_syscall = self
            .precompile_events
            .iter_mut()
            .pico_bridge()
            .map(|(syscall_code, events)| {
                let mut local_records = Vec::new();
                if events.is_empty() {
                    return (local_records, None);
                }

                let threshold = effective_threshold(*syscall_code);

                // Skip the extract+sort+putback churn when this bucket can't emit a chunk yet:
                // a below-threshold non-last batch would swap_remove every committed event, sort
                // them (moving the large EC/keccak event structs), then `extend` them straight
                // back — pure churn repeated every batch (e.g. SECP256K1_DOUBLE/ADD do not reach
                // their thresholds until `last`). A cheap count (no moves) lets us bail; the events
                // stay in place and the identical set is sorted/split once it can actually emit.
                let n_committed = events
                    .iter()
                    .filter(|e| e.0.chunk <= committed_chunk)
                    .count();
                if n_committed < threshold && !last {
                    return (local_records, None);
                }

                let mut committed = Vec::new();

                // 1. Extract committed events using swap_remove (O(N) scan, O(1) removal)
                let mut i = 0;
                while i < events.len() {
                    if events[i].0.chunk <= committed_chunk {
                        committed.push(events.swap_remove(i));
                        // Don't increment i, check the swapped-in element
                    } else {
                        i += 1;
                    }
                }

                if committed.is_empty() {
                    return (local_records, None);
                }

                // 2. Sort committed events by (chunk, clk) for deterministic order
                committed.sort_by_key(|(se, _)| {
                    let clk32: u32 = se.clk.try_into().expect("SyscallEvent.clk overflows u32");
                    ((se.chunk as u64) << 32) | (clk32 as u64)
                });

                // 3. Split by threshold
                let mut committed_iter = committed.into_iter();
                loop {
                    // Check if we have enough for a full chunk
                    if ExactSizeIterator::len(&committed_iter) < threshold {
                        break;
                    }

                    let chunk: Vec<_> = committed_iter.by_ref().take(threshold).collect();
                    let mut rec = EmulationRecord::new(program.clone());
                    rec.is_cpu_chunk = false;
                    rec.precompile_events.insert(*syscall_code, chunk);
                    merge_precompile_local_mem(&mut rec.precompile_events);
                    local_records.push(rec);
                }

                // 4. Remainder: hand back for its own tail record (last) or put back for next batch
                let mut remainder_out = None;
                let remainder: Vec<_> = committed_iter.collect();
                if !remainder.is_empty() {
                    if last {
                        if deferred_tail_merge() {
                            remainder_out = Some((*syscall_code, remainder));
                        } else {
                            // Legacy: one standalone record per syscall remainder.
                            let mut rec = EmulationRecord::new(program.clone());
                            rec.is_cpu_chunk = false;
                            rec.precompile_events.insert(*syscall_code, remainder);
                            merge_precompile_local_mem(&mut rec.precompile_events);
                            local_records.push(rec);
                        }
                    } else {
                        // Put back remaining committed events for next batch
                        events.extend(remainder);
                    }
                }
                (local_records, remainder_out)
            })
            .collect::<Vec<_>>();

        let mut chunk_records: Vec<EmulationRecord> = Vec::new();
        let mut remainders = Vec::new();
        for (records, remainder) in per_syscall {
            chunk_records.extend(records);
            if let Some(r) = remainder {
                remainders.push(r);
            }
        }

        // Sort records deterministically to ensure consistent order across runs/machines
        // IMPORTANT: We must find the syscall_code with actual events, not just iter().next()
        // because PrecompileEvents::default() pre-inserts empty Vecs for all syscall_codes,
        // and HashMap iteration order is non-deterministic across machines.
        chunk_records.sort_by(|a, b| {
            let get_info = |rec: &EmulationRecord| {
                // Find the first syscall_code that has non-empty events
                for (code, events) in rec.precompile_events.iter() {
                    if !events.is_empty() {
                        // Use first event's chunk and clk as secondary sort key
                        let first_key = events
                            .first()
                            .map(|(se, _)| {
                                let clk32: u32 =
                                    se.clk.try_into().expect("SyscallEvent.clk overflows u32");
                                ((se.chunk as u64) << 32) | (clk32 as u64)
                            })
                            .unwrap_or(0);
                        return Some((*code, first_key));
                    }
                }
                None
            };

            match (get_info(a), get_info(b)) {
                (Some((code_a, key_a)), Some((code_b, key_b))) => match code_a.cmp(&code_b) {
                    std::cmp::Ordering::Equal => key_a.cmp(&key_b),
                    other => other,
                },
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            }
        });

        // Tail records: one record per precompile remainder, then memory-only records for the
        // deferred init/finalize buckets. Full blocks above are untouched; tail records sit at a
        // fixed position after them. A remainder never shares a record with another kind or
        // with memory, so every tail record has one of the shapes the production shape system
        // enumerates: a single precompile chip with its companion chips, or the memory family.
        // (A record mixing k kinds would need a shape per combination of k independent heights;
        // with the 17 kinds that leave remainders that is far beyond any enumerable set.) A
        // remainder is smaller than a full block of its kind, so it needs no budget of its own.
        //
        // Determinism: remainders are taken in ascending syscall_code order, and each
        // remainder's events are already (chunk, clk)-sorted above.
        if last {
            let new_tail_record = |program: &Arc<Program>| {
                let mut rec = EmulationRecord::new(program.clone());
                rec.is_cpu_chunk = false;
                rec
            };

            let mut current = new_tail_record(&program);
            let mut occupied = false;

            // 1) Precompile remainders, one record each.
            remainders.sort_by_key(|(code, _)| *code);
            for (syscall_code, remainder) in remainders {
                if occupied {
                    chunk_records.push(std::mem::replace(&mut current, new_tail_record(&program)));
                }
                current.precompile_events.insert(syscall_code, remainder);
                merge_precompile_local_mem(&mut current.precompile_events);
                occupied = true;
            }
            if occupied {
                chunk_records.push(std::mem::replace(&mut current, new_tail_record(&program)));
                occupied = false;
            }

            // 2) Deferred memory. The finalize stream is bucketed (DEFERRED_MEMORY_BUCKET) and
            // the buckets packed into memory-only records under the cells budget, the
            // memory-event cap and the GKR-leaves line; the initialize stream -- the registers
            // and the nonzero hint-written words only: a zero-initial word's first-touch
            // MemoryLocal entry declares its initial state and gets no MemoryInitialize event
            // (`riscv_memory/event.rs`) -- is bucketed the same way and
            // appended to the last record, opening records of its own when it would not fit
            // (`deferred_memory_blocks`). Bucketing keeps the deferred Global chip at exactly a
            // power of two; a block costs mem_tail_padded_cost (pow2-padded Global + Poseidon2
            // area). Address chaining is preserved: each stream is consumed as contiguous
            // sorted slices in order, and each record carrying memory sets previous_*/last_*
            // limbs (previous_* on its first block). A record without MemoryInitialize keeps
            // `previous_init == last_init`, the frozen cursor the recursion checks for a chunk
            // without that chip (`mle/compiler/recursion/lowering.rs`), so only the record with
            // the init block moves it, and the finalize cursor is frozen the same way on an
            // init-only record.
            self.memory_initialize_events
                .sort_by_key(|event| event.addr);
            self.memory_finalize_events.sort_by_key(|event| event.addr);
            let mut init_addr_limbs = [0u32; 3];
            let mut finalize_addr_limbs = [0u32; 3];
            let _ = opts.memory;
            let fold_memory = deferred_tail_merge();
            let budget = TAIL_MERGE_BUDGET_CELLS;
            let mut acc: u64 = 0;
            // GKR-leaves line: a record also closes before its estimated logup-GKR leaves
            // cross the 2^28 allocation step (see TAIL_MERGE_MAX_GKR_LEAVES).
            let program_rows = program.instructions.len() as u64;
            let mut gkr_leaves = TailGkrLeavesAccount::new(program_rows);
            // Every memory record closes under the one proven cap (`TAIL_MERGE_MAX_MEM_EVENTS`).
            for (init_range, finalize_range) in deferred_memory_blocks(
                self.memory_initialize_events.len(),
                self.memory_finalize_events.len(),
            ) {
                let mem_init_chunk = &self.memory_initialize_events[init_range];
                let mem_finalize_chunk = &self.memory_finalize_events[finalize_range];
                if fold_memory {
                    let cost = mem_tail_padded_cost(
                        (mem_init_chunk.len() + mem_finalize_chunk.len()) as u64,
                    );
                    let block_events = mem_init_chunk.len() + mem_finalize_chunk.len();
                    let current_mem_events = current.memory_initialize_events.len()
                        + current.memory_finalize_events.len();
                    let mut leaves_probe = gkr_leaves;
                    leaves_probe
                        .add_memory(mem_init_chunk.len() as u64, mem_finalize_chunk.len() as u64);
                    if occupied
                        && (acc.saturating_add(cost) > budget
                            // `>=`: keep every tail chunk strictly below the cap. The Global
                            // chip (one row per memory event here) pads to a power of two and
                            // needs at least one padding row (its last row must be non-real), so
                            // exactly 2^22 events would double the trace in natural mode and
                            // overflow the fixed 2^22 bucket in bucket mode. Buckets are sized
                            // one under 2^20 (DEFERRED_MEMORY_BUCKET) so four buckets stay at
                            // 2^22 - 4 and fit; this guard then closes on the fifth, and on the
                            // init block when it would reach the cap.
                            || current_mem_events + block_events >= TAIL_MERGE_MAX_MEM_EVENTS
                            || leaves_probe.total_leaves() > TAIL_MERGE_MAX_GKR_LEAVES)
                    {
                        chunk_records
                            .push(std::mem::replace(&mut current, new_tail_record(&program)));
                        acc = 0;
                        gkr_leaves = TailGkrLeavesAccount::new(program_rows);
                    }
                    gkr_leaves
                        .add_memory(mem_init_chunk.len() as u64, mem_finalize_chunk.len() as u64);
                    if current.memory_initialize_events.is_empty()
                        && current.memory_finalize_events.is_empty()
                    {
                        current.public_values.previous_init_addr_limbs = init_addr_limbs;
                        current.public_values.previous_finalize_addr_limbs = finalize_addr_limbs;
                    }
                    current
                        .memory_initialize_events
                        .extend_from_slice(mem_init_chunk);
                    if let Some(last_event) = mem_init_chunk.last() {
                        init_addr_limbs = encode_proof_addr_48(last_event.addr);
                    }
                    current.public_values.last_init_addr_limbs = init_addr_limbs;

                    current
                        .memory_finalize_events
                        .extend_from_slice(mem_finalize_chunk);
                    if let Some(last_event) = mem_finalize_chunk.last() {
                        finalize_addr_limbs = encode_proof_addr_48(last_event.addr);
                    }
                    current.public_values.last_finalize_addr_limbs = finalize_addr_limbs;

                    acc = acc.saturating_add(cost);
                    occupied = true;
                } else {
                    // Legacy: one standalone deferred-memory record per block (a finalize
                    // bucket, or the init block).
                    let mut memory_chunk = new_tail_record(&program);
                    memory_chunk
                        .memory_initialize_events
                        .extend_from_slice(mem_init_chunk);
                    memory_chunk.public_values.previous_init_addr_limbs = init_addr_limbs;
                    if let Some(last_event) = mem_init_chunk.last() {
                        init_addr_limbs = encode_proof_addr_48(last_event.addr);
                    }
                    memory_chunk.public_values.last_init_addr_limbs = init_addr_limbs;

                    memory_chunk
                        .memory_finalize_events
                        .extend_from_slice(mem_finalize_chunk);
                    memory_chunk.public_values.previous_finalize_addr_limbs = finalize_addr_limbs;
                    if let Some(last_event) = mem_finalize_chunk.last() {
                        finalize_addr_limbs = encode_proof_addr_48(last_event.addr);
                    }
                    memory_chunk.public_values.last_finalize_addr_limbs = finalize_addr_limbs;

                    chunk_records.push(memory_chunk);
                }
            }

            if occupied {
                chunk_records.push(current);
            }
        }

        // `CHUNK_SPLIT_DEBUG=1` (default silent): tail-chunk composition — which syscall (or
        // deferred memory init/finalize) each non-CPU chunk carries and how many events, the
        // input for the tail-merge decision.
        if super::chunk_split::split_debug() {
            for (i, rec) in chunk_records.iter().enumerate() {
                // Sort by syscall_code so the probe output is diff-able across runs
                // (precompile_events is a HashMap; its iteration order is not stable).
                let mut items: Vec<_> = rec
                    .precompile_events
                    .iter()
                    .filter(|(_, events)| !events.is_empty())
                    .map(|(code, events)| (*code, events.len()))
                    .collect();
                items.sort_by_key(|(code, _)| *code);
                let precompile: Vec<String> = items
                    .into_iter()
                    .map(|(code, n)| format!("{code:?}x{n}"))
                    .collect();
                // Which events, not just how many: an event that lands in the wrong record
                // leaves every full block exactly `threshold` long, so the counts above cannot
                // see it. The pair is the (chunk, clk) key the split orders on.
                let groups = rec.precompile_events.sorted_groups();
                let key = |(se, _): &(SyscallEvent, PrecompileEvent)| (se.chunk, se.clk);
                let first_key = groups.first().and_then(|(_, e)| e.first()).map(key);
                let last_key = groups.last().and_then(|(_, e)| e.last()).map(key);
                // Estimated GKR-leaf account of the record, for calibration against
                // the prover's `G3_MEASURE=1` per-chunk total_interactions.
                let mut leaves = TailGkrLeavesAccount::new(rec.program.instructions.len() as u64);
                for (code, events) in rec.precompile_events.iter() {
                    if !events.is_empty() {
                        leaves.add_precompile(
                            *code,
                            events.len() as u64,
                            events.get_local_mem_events().into_iter().count() as u64,
                        );
                    }
                }
                leaves.add_memory(
                    rec.memory_initialize_events.len() as u64,
                    rec.memory_finalize_events.len() as u64,
                );
                tracing::info!(
                    "[chunk-split] tail-chunk {i} (last={last}): precompile=[{}] first_key={first_key:?} last_key={last_key:?} mem_init={} mem_finalize={} gkr_leaves~{}",
                    precompile.join(", "),
                    rec.memory_initialize_events.len(),
                    rec.memory_finalize_events.len(),
                    leaves.total_leaves(),
                );
            }
        }

        chunk_records
    }
}

/// The local-memory entries one precompile event carries: the per-event view of
/// [`PrecompileLocalMemory`], which only flattens a whole group and so loses which syscall an
/// entry belongs to.
fn precompile_local_mem(event: &PrecompileEvent) -> &[MemoryLocalEvent] {
    match event {
        PrecompileEvent::ShaExtend(e) => &e.local_mem_access,
        PrecompileEvent::ShaCompress(e) => &e.local_mem_access,
        PrecompileEvent::KeccakPermute(e) => &e.local_mem_access,
        PrecompileEvent::EdDecompress(e) => &e.local_mem_access,
        PrecompileEvent::EdAdd(e)
        | PrecompileEvent::Secp256k1Add(e)
        | PrecompileEvent::Secp256r1Add(e)
        | PrecompileEvent::Bn254Add(e)
        | PrecompileEvent::Bls12381Add(e) => &e.local_mem_access,
        PrecompileEvent::Secp256k1Double(e)
        | PrecompileEvent::Secp256r1Double(e)
        | PrecompileEvent::Bn254Double(e)
        | PrecompileEvent::Bls12381Double(e) => &e.local_mem_access,
        PrecompileEvent::Secp256k1Decompress(e)
        | PrecompileEvent::Secp256r1Decompress(e)
        | PrecompileEvent::K256Decompress(e)
        | PrecompileEvent::Bls12381Decompress(e) => &e.local_mem_access,
        PrecompileEvent::Bn254Fp(e)
        | PrecompileEvent::Bls12381Fp(e)
        | PrecompileEvent::Secp256k1Fp(e) => &e.local_mem_access,
        PrecompileEvent::Bn254Fp2AddSub(e) | PrecompileEvent::Bls12381Fp2AddSub(e) => {
            &e.local_mem_access
        }
        PrecompileEvent::Bn254Fp2Mul(e) | PrecompileEvent::Bls12381Fp2Mul(e) => &e.local_mem_access,
        PrecompileEvent::Uint256Mul(e) => &e.local_mem_access,
        PrecompileEvent::Poseidon2Permute(e) => &e.local_mem_access,
    }
}

/// Mutable twin of [`precompile_local_mem`]: the same match arms, handing out the entry vector
/// itself so a caller can rewrite and drop entries.
fn precompile_local_mem_mut(event: &mut PrecompileEvent) -> &mut Vec<MemoryLocalEvent> {
    match event {
        PrecompileEvent::ShaExtend(e) => &mut e.local_mem_access,
        PrecompileEvent::ShaCompress(e) => &mut e.local_mem_access,
        PrecompileEvent::KeccakPermute(e) => &mut e.local_mem_access,
        PrecompileEvent::EdDecompress(e) => &mut e.local_mem_access,
        PrecompileEvent::EdAdd(e)
        | PrecompileEvent::Secp256k1Add(e)
        | PrecompileEvent::Secp256r1Add(e)
        | PrecompileEvent::Bn254Add(e)
        | PrecompileEvent::Bls12381Add(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Double(e)
        | PrecompileEvent::Secp256r1Double(e)
        | PrecompileEvent::Bn254Double(e)
        | PrecompileEvent::Bls12381Double(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Decompress(e)
        | PrecompileEvent::Secp256r1Decompress(e)
        | PrecompileEvent::K256Decompress(e)
        | PrecompileEvent::Bls12381Decompress(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp(e)
        | PrecompileEvent::Bls12381Fp(e)
        | PrecompileEvent::Secp256k1Fp(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp2AddSub(e) | PrecompileEvent::Bls12381Fp2AddSub(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Bn254Fp2Mul(e) | PrecompileEvent::Bls12381Fp2Mul(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Uint256Mul(e) => &mut e.local_mem_access,
        PrecompileEvent::Poseidon2Permute(e) => &mut e.local_mem_access,
    }
}

/// Merge the MemoryLocal entries of one freshly formed precompile record.
///
/// Every precompile syscall carries its own local-memory table, one entry per address it touched
/// (`syscalls/syscall_context.rs`; addresses are aligned dwords). When two calls of the same
/// kind in the same emulation chunk touch the same address back to back, the earlier call's
/// `final_mem_access` and the later call's `initial_mem_access` are the same record: on the
/// Global bus the earlier entry sends it
/// and the later entry receives it, and on the Regional bus the later call's first access
/// looks it up as `prev` (`looking`) while the later entry provides it as `initial` (`looked`).
/// Both pairs cancel inside this one proof, so the two entries collapse into
/// `{addr, earlier.initial, later.final}` and the record loses one entry per merge (two Global
/// events and two Regional tuples' worth of Memory-bus
/// traffic). The MemoryLocal AIR is untouched: the merged entry still has `final_chunk` equal to
/// the chunk of its initial access when both calls sit in one chunk (`final_clk - initial_clk -
/// 1` stays below 2^25), and an initial access from an earlier chunk keeps the `starts_earlier`
/// path of the first entry unchanged.
///
/// Strictly record-local: a handoff between two records has to stay on the Global bus, because
/// the two proofs' Regional buses balance separately. CPU records and memory records never pass
/// through here. Deterministic: the result depends only on the (chunk, clk)-sorted input order.
fn merge_precompile_local_mem(events: &mut PrecompileEvents) {
    if !precompile_local_mem_merge_enabled() {
        return;
    }
    for (code, group) in events.iter_mut() {
        if group.is_empty() {
            continue;
        }
        let before: usize = group
            .iter()
            .map(|(_, pe)| precompile_local_mem(pe).len())
            .sum();
        let merges = merge_precompile_local_mem_inner(group);
        if merges > 0 {
            tracing::debug!(
                "[local-mem-merge] {code:?}: merged {merges} of {before} local-memory entries over {} calls",
                group.len()
            );
        }
    }
}

/// The merge itself for one syscall kind's group, which must be sorted by `(chunk, clk)` of its
/// `SyscallEvent` (split sorts every group it forms). Returns the number of entries removed.
///
/// One pass over the entries in event order, keeping for each `(SyscallEvent.chunk, addr)` the
/// position of the open entry (the last one not yet closed by a mismatch). An entry whose
/// `initial_mem_access` equals the open entry's `final_mem_access` (chunk, timestamp and value)
/// extends the open entry's final access and is dropped; any other entry becomes the open one.
/// Dropped entries are marked and removed at the end with `retain`, so the entry order inside
/// every event is preserved and the open-entry positions stay valid during the pass. O(entries).
fn merge_precompile_local_mem_inner(group: &mut [(SyscallEvent, PrecompileEvent)]) -> usize {
    debug_assert!(
        group
            .windows(2)
            .all(|w| (w[0].0.chunk, w[0].0.clk) <= (w[1].0.chunk, w[1].0.clk)),
        "precompile group must be (chunk, clk)-sorted before merging"
    );
    let mut open: HashMap<(RvChunk, RvAddr), (usize, usize)> = HashMap::new();
    // (event index, entry index) of every dropped entry, in scan order, hence sorted.
    let mut dropped: Vec<(usize, usize)> = Vec::new();
    for i in 0..group.len() {
        let chunk = group[i].0.chunk;
        let n = precompile_local_mem(&group[i].1).len();
        for j in 0..n {
            let e = precompile_local_mem(&group[i].1)[j];
            let key = (chunk, e.addr);
            let extends_open = open.get(&key).copied().filter(|&(oi, oj)| {
                precompile_local_mem(&group[oi].1)[oj].final_mem_access == e.initial_mem_access
            });
            match extends_open {
                Some((oi, oj)) => {
                    precompile_local_mem_mut(&mut group[oi].1)[oj].final_mem_access =
                        e.final_mem_access;
                    dropped.push((i, j));
                }
                None => {
                    open.insert(key, (i, j));
                }
            }
        }
    }
    let merges = dropped.len();
    let mut k = 0;
    while k < merges {
        let i = dropped[k].0;
        let start = k;
        while k < merges && dropped[k].0 == i {
            k += 1;
        }
        let idxs = &dropped[start..k];
        let (mut next, mut j) = (0usize, 0usize);
        precompile_local_mem_mut(&mut group[i].1).retain(|_| {
            let drop_it = next < idxs.len() && idxs[next].1 == j;
            next += usize::from(drop_it);
            j += 1;
            !drop_it
        });
    }
    merges
}

impl Drop for EmulationRecord {
    fn drop(&mut self) {
        // Return CPU event buffer to global pool
        let buffer = std::mem::replace(&mut self.cpu_events, CpuEventBuffer::empty());
        return_cpu_event_buffer(buffer);
        // Return ALU event buffers to global pool
        let buffer = std::mem::replace(&mut self.add_sub_events, AluEventBuffer::empty());
        return_alu_event_buffer(buffer);
        let buffer = std::mem::replace(&mut self.lt_events, AluEventBuffer::empty());
        return_alu_event_buffer(buffer);
    }
}

impl RecordBehavior for EmulationRecord {
    fn name(&self) -> String {
        "RiscvEmulationRecord".to_string()
    }

    fn stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert("Cpu Events".to_string(), self.cpu_events.len());

        /*
        Arithmetic-related
         */
        stats.insert("Add Sub Events".to_string(), self.add_sub_events.len());
        stats.insert("Mul Events".to_string(), self.mul_events.len());
        stats.insert("Bitwise Events".to_string(), self.bitwise_events.len());
        stats.insert(
            "Shift Left Events".to_string(),
            self.shift_left_events.len(),
        );
        stats.insert(
            "Shift Right Events".to_string(),
            self.shift_right_events.len(),
        );
        stats.insert("Divrem Events".to_string(), self.divrem_events.len());
        stats.insert("Lt Events".to_string(), self.lt_events.len());
        stats.insert(
            "RISCV Poseidon2 Events".to_string(),
            self.poseidon2_events.len(),
        );

        /*
        Memory-related
         */
        stats.insert(
            "Memory Initialize Events".to_string(),
            self.memory_initialize_events.len(),
        );
        stats.insert(
            "Memory Finalize Events".to_string(),
            self.memory_finalize_events.len(),
        );
        stats.insert(
            "Memory Read-Write Events".to_string(),
            self.memory_read_write_event_indices.len(),
        );
        stats.insert(
            "Local Memory Access Events".to_string(),
            self.cpu_local_memory_access.len(),
        );

        /*
        Lookup-related
         */
        stats.insert("Global Events".to_string(), self.global_lookup_events.len());
        stats.insert("Byte Lookups".to_string(), self.byte_lookups.len());

        /*
        Syscall-related
         */
        for (syscall_code, events) in self.precompile_events.iter() {
            stats.insert(format!("syscall {syscall_code:?}"), events.len());
        }

        // Filter out the empty events.
        stats.retain(|_, v| *v != 0);
        stats
    }

    fn append(&mut self, extra: &mut EmulationRecord) {
        // Handle CPU events.
        // Fast-path: if destination has an empty buffer, move the entire buffer from extra.
        match (&mut self.cpu_events, &mut extra.cpu_events) {
            (CpuEventBuffer::Empty, CpuEventBuffer::Buffer(_)) => {
                let moved = std::mem::replace(&mut extra.cpu_events, CpuEventBuffer::empty());
                self.cpu_events = moved;
            }
            (CpuEventBuffer::Buffer(dst), CpuEventBuffer::Buffer(_)) if dst.is_empty() => {
                // Swap entire buffers to avoid copying when destination is empty
                std::mem::swap(&mut self.cpu_events, &mut extra.cpu_events);
            }
            _ => {
                // Otherwise, copy as many as fit and clear the source
                let extra_slice = extra.cpu_events.as_slice();
                if !extra_slice.is_empty() {
                    let _ = self.add_cpu_events(extra_slice);
                }
                extra.clear_cpu_events();
            }
        }

        // Append all other events.
        self.memory_read_write_event_indices
            .append(&mut extra.memory_read_write_event_indices);
        self.add_sub_events.append_from(&mut extra.add_sub_events);
        self.mul_events.append(&mut extra.mul_events);
        self.bitwise_events.append(&mut extra.bitwise_events);
        self.shift_left_events.append(&mut extra.shift_left_events);
        self.shift_right_events
            .append(&mut extra.shift_right_events);
        self.divrem_events.append(&mut extra.divrem_events);
        self.lt_events.append_from(&mut extra.lt_events);
        self.memory_initialize_events
            .append(&mut extra.memory_initialize_events);
        self.memory_finalize_events
            .append(&mut extra.memory_finalize_events);
        self.cpu_local_memory_access
            .append(&mut extra.cpu_local_memory_access);
        self.syscall_events.append(&mut extra.syscall_events);
        self.precompile_events.append(&mut extra.precompile_events);
        if self.byte_lookups.is_empty() {
            self.byte_lookups = std::mem::take(&mut extra.byte_lookups);
        } else {
            for (event, mult) in &extra.byte_lookups {
                *self.byte_lookups.entry(*event).or_insert(0) += mult;
            }
        }
        self.poseidon2_events.append(&mut extra.poseidon2_events);
        self.global_lookup_events
            .append(&mut extra.global_lookup_events);
    }

    fn public_values<F: PrimeCharacteristicRing>(&self) -> Vec<F> {
        // The tally is read off the events rather than kept by the emulator, which carries the
        // rest of the public values from one chunk into the next.
        let mut pvs = self.public_values;
        (pvs.deferred_commits, pvs.deferred_commit_mask) =
            crate::chips::chips::riscv_ecall::traces::deferred_commit_tally(
                self.cpu_events.as_slice(),
            );
        pvs.to_vec()
    }

    fn chunk_index(&self) -> usize {
        self.public_values.chunk as usize
    }
}

#[derive(Debug, Copy, Clone, Default)]
pub struct MemoryAccessRecord {
    /// The memory access of the `a` register.
    pub a: Option<MemoryRecordEnum>,
    /// The memory access of the `b` register.
    pub b: Option<MemoryRecordEnum>,
    /// The memory access of the `c` register.
    pub c: Option<MemoryRecordEnum>,
    /// The memory access of the `memory` register.
    pub memory: Option<MemoryRecordEnum>,
}

impl ByteRecordBehavior for EmulationRecord {
    fn add_byte_lookup_event(&mut self, blu_event: ByteLookupEvent) {
        *self.byte_lookups.entry(blu_event).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::EmulationRecord;
    use crate::{
        chips::chips::alu::event::AluEvent,
        compiler::riscv::{opcode::Opcode, program::Program},
        emulator::riscv::{
            alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
            event_pool::HostAllocFlags,
        },
    };
    use hashbrown::HashMap;
    use std::sync::Arc;

    #[test]
    fn add_alu_events_accepts_wide_rv64_opcode_families() {
        // ADD/SUB and SLT land in buffers drawn from this pool.
        if !is_alu_pool_initialized() {
            init_alu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
        }
        let mut record = EmulationRecord::new(Arc::new(Program::default()));
        let mut grouped = HashMap::new();

        grouped.insert(
            Opcode::ADDW,
            vec![AluEvent::new(1, Opcode::ADDW, 1, 2, 3, false)],
        );
        grouped.insert(
            Opcode::SUBW,
            vec![AluEvent::new(2, Opcode::SUBW, 4, 5, 6, false)],
        );
        grouped.insert(
            Opcode::SLLW,
            vec![AluEvent::new(3, Opcode::SLLW, 7, 8, 9, false)],
        );
        grouped.insert(
            Opcode::SRLW,
            vec![AluEvent::new(4, Opcode::SRLW, 10, 11, 12, false)],
        );
        grouped.insert(
            Opcode::SRAW,
            vec![AluEvent::new(5, Opcode::SRAW, 13, 14, 15, false)],
        );
        grouped.insert(
            Opcode::MULW,
            vec![AluEvent::new(6, Opcode::MULW, 16, 17, 18, false)],
        );
        grouped.insert(
            Opcode::DIVW,
            vec![AluEvent::new(7, Opcode::DIVW, 19, 20, 21, false)],
        );
        grouped.insert(
            Opcode::DIVUW,
            vec![AluEvent::new(8, Opcode::DIVUW, 22, 23, 24, false)],
        );
        grouped.insert(
            Opcode::REMW,
            vec![AluEvent::new(9, Opcode::REMW, 25, 26, 27, false)],
        );
        grouped.insert(
            Opcode::REMUW,
            vec![AluEvent::new(10, Opcode::REMUW, 28, 29, 30, false)],
        );

        record.add_alu_events(grouped);

        // ADDW and SUBW share one buffer here.
        assert_eq!(record.add_sub_events.len(), 2);
        assert_eq!(record.shift_left_events.len(), 1);
        assert_eq!(record.shift_right_events.len(), 2);
        assert_eq!(record.mul_events.len(), 1);
        assert_eq!(record.divrem_events.len(), 4);
    }
}

/// Binds the tail-merge GKR-leaf interaction constants to the AIRs they are supposed to describe.
///
/// These are hand-derived per-row interaction counts. Unlike the widths in `tail_rows_and_width`
/// (`size_of`-derived, so they track their AIRs automatically) nothing makes them follow an AIR
/// change. They only steer packing, never soundness — but **under**-counting is the dangerous
/// direction: it lets a record cross the 2^28-leaf line undetected, which doubles the logup-GKR
/// allocation from 8 GiB to 16 GiB and can OOM a 32 GB card. An under-count is also invisible on
/// inspection: `SHA_EXTEND` shipped as `61`, which is that chip's *constraint* count sitting one
/// column away from its interaction count (81) in the same keygen log line. So assert the counts
/// against what keygen actually derives, through the same path the prover uses.
#[cfg(test)]
mod tail_merge_constants {
    use super::{
        tail_gkr_interactions, tail_rows_and_width, TAIL_GKR_BYTE_LEAVES,
        TAIL_GKR_FALLBACK_INTERACTIONS, TAIL_GKR_GLOBAL_INTERACTIONS,
        TAIL_GKR_INIT_FIN_INTERACTIONS, TAIL_GKR_MEMORY_LOCAL_INTERACTIONS,
        TAIL_GKR_POSEIDON2_INTERACTIONS, TAIL_GKR_SYSCALL_INTERACTIONS,
    };
    use crate::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::riscv::syscalls::SyscallCode,
        mle::machine::riscv::{air_id, mle_riscv_air_refs, RISCV_APP_PREP_AIR_IDS},
    };
    use pico_mle_core::{config::riscv_params_with_100_bits_security, StarkEngine};
    use pico_mle_cpu::KoalaBearPoseidon2CpuEngine;
    use std::sync::Arc;

    #[test]
    fn interaction_counts_match_their_airs() {
        // Any log_stacked_height keygens the same AIR set; interaction counts are structural.
        let engine: KoalaBearPoseidon2CpuEngine =
            StarkEngine::new(riscv_params_with_100_bits_security(20));
        // Keygen builds the Program chip's preprocessed table, which debug-asserts a non-empty
        // instruction list, so `Program::default()` will not do. Interaction counts are structural
        // — they do not depend on what the program computes — so one instruction is enough.
        // The base sits inside the guest address range: the Program chip's preprocessed table
        // asserts every pc below `0x7800_0000` at keygen (`riscv_program/traces.rs`), and a `Pc`
        // has two u16 limbs, so a base at or above 2^32 would fail keygen here.
        let program = Arc::new(Program::new(
            vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, false)],
            0x1000_0000,
            0x1000_0000,
        ));
        let airs = mle_riscv_air_refs(program, false);
        let (pk, _) = engine.keygen_with_app_prep(&airs, RISCV_APP_PREP_AIR_IDS);

        // `air_name` carries the chip's generic parameters, so a prefix plus (for the curve chips)
        // a parameter fragment identifies one AIR exactly. Requiring a unique match is deliberate:
        // if the AIR set changes shape this fails loudly instead of silently asserting nothing.
        let measured = |prefix: &str, param: Option<&str>| -> u64 {
            let hits: Vec<_> = pk
                .per_air
                .iter()
                .filter(|a| {
                    a.air_name.starts_with(prefix) && param.is_none_or(|p| a.air_name.contains(p))
                })
                .collect();
            assert_eq!(
                hits.len(),
                1,
                "expected exactly one AIR matching {prefix:?}/{param:?}, found {:?}",
                hits.iter().map(|a| &a.air_name).collect::<Vec<_>>()
            );
            hits[0].vk.num_interactions() as u64
        };

        // Record-shared chips multiply into *every* deferred record, so an error here is systemic
        // rather than confined to one syscall.
        assert_eq!(
            measured("GcsBindAir", None),
            TAIL_GKR_GLOBAL_INTERACTIONS,
            "TAIL_GKR_GLOBAL_INTERACTIONS is stale"
        );
        assert_eq!(
            measured("Poseidon2ChipP3", None),
            TAIL_GKR_POSEIDON2_INTERACTIONS,
            "TAIL_GKR_POSEIDON2_INTERACTIONS is stale"
        );
        assert_eq!(
            measured("MemoryLocalChip", None),
            TAIL_GKR_MEMORY_LOCAL_INTERACTIONS,
            "TAIL_GKR_MEMORY_LOCAL_INTERACTIONS is stale"
        );
        // Initialize and Finalize are two AIRs of one type; both must match the single constant.
        for a in pk
            .per_air
            .iter()
            .filter(|a| a.air_name.starts_with("MemoryInitializeFinalizeChip"))
        {
            assert_eq!(
                a.vk.num_interactions() as u64,
                TAIL_GKR_INIT_FIN_INTERACTIONS,
                "TAIL_GKR_INIT_FIN_INTERACTIONS is stale for {}",
                a.air_name
            );
        }
        for a in pk
            .per_air
            .iter()
            .filter(|a| a.air_name.starts_with("SyscallChip"))
        {
            assert_eq!(
                a.vk.num_interactions() as u64,
                TAIL_GKR_SYSCALL_INTERACTIONS,
                "TAIL_GKR_SYSCALL_INTERACTIONS is stale for {}",
                a.air_name
            );
        }

        // The catch-all bounds every AIR not in the table below, so it has to sit above the
        // widest one in the machine -- under-counting there is what lets a record cross the
        // 2^28-leaf line undetected.
        let widest = pk
            .per_air
            .iter()
            .map(|a| a.vk.num_interactions() as u64)
            .max()
            .expect("keygen produced no AIRs");
        assert!(
            widest <= TAIL_GKR_FALLBACK_INTERACTIONS,
            "TAIL_GKR_FALLBACK_INTERACTIONS={TAIL_GKR_FALLBACK_INTERACTIONS} under-counts the \
             widest AIR ({widest})"
        );
        // The byte table's per-row count is the largest single term in `base_leaves`, and the
        // Program table's is the multiplier on the instruction count. Both were hand-copied.
        assert_eq!(
            pk.per_air[air_id::BYTE].vk.num_interactions() as u64 * (1 << 17),
            TAIL_GKR_BYTE_LEAVES,
            "TAIL_GKR_BYTE_LEAVES is stale"
        );
        assert_eq!(
            pk.per_air[air_id::PROGRAM].vk.num_interactions(),
            1,
            "Program is no longer 1 interaction/row, so `lift(program_instructions)` under-counts"
        );

        // Every entry of the per-precompile table, against its own AIR. Keep this list in step with
        // `tail_gkr_interactions`: a syscall present there but missing here is untested.
        let table: &[(SyscallCode, &str, Option<&str>)] = &[
            (SyscallCode::SHA_EXTEND, "ShaExtendChip", None),
            (SyscallCode::SHA_COMPRESS, "ShaCompressChip", None),
            (
                SyscallCode::SECP256K1_ADD,
                "WeierstrassAddAssignChip",
                Some("Secp256k1Parameters"),
            ),
            (
                SyscallCode::BN254_ADD,
                "WeierstrassAddAssignChip",
                Some("Bn254Parameters"),
            ),
            (
                SyscallCode::SECP256K1_DOUBLE,
                "WeierstrassDoubleAssignChip",
                Some("Secp256k1Parameters"),
            ),
            (
                SyscallCode::BN254_DOUBLE,
                "WeierstrassDoubleAssignChip",
                Some("Bn254Parameters"),
            ),
            (
                SyscallCode::BN254_FP_ADD,
                "FpOpChip",
                Some("Bn254BaseField"),
            ),
            (
                SyscallCode::BN254_FP2_ADD,
                "Fp2AddSubChip",
                Some("Bn254BaseField"),
            ),
            (
                SyscallCode::BN254_FP2_MUL,
                "Fp2MulChip",
                Some("Bn254BaseField"),
            ),
            (
                SyscallCode::BLS12381_FP_ADD,
                "FpOpChip",
                Some("Bls381BaseField"),
            ),
            (
                SyscallCode::BLS12381_FP2_MUL,
                "Fp2MulChip",
                Some("Bls381BaseField"),
            ),
            (SyscallCode::UINT256_MUL, "Uint256MulChip", None),
        ];
        // Collect every mismatch rather than tripping on the first: the constants move as a
        // group when a shared gadget changes, and one-at-a-time bisecting hides the pattern.
        let mut stale = Vec::new();
        for &(code, prefix, param) in table {
            let expected = tail_gkr_interactions(code)
                .unwrap_or_else(|| panic!("{code:?} has no tail_gkr_interactions entry"));
            let actual = measured(prefix, param);
            println!("MEASURED {code:?} = {actual} (constant {expected})");
            if actual != expected {
                stale.push(format!("{code:?}: measured {actual}, constant {expected}"));
            }
        }
        assert!(
            stale.is_empty(),
            "tail_gkr_interactions is stale:\n  {}",
            stale.join("\n  ")
        );

        // KECCAK_PERMUTE is not in that table. Its syscall, memory and range-check work lives
        // in the sibling `KeccakControlChip` -- one row per permutation, where the permute chip
        // has 24 -- which leaves the permute AIR at two interactions a row while the constant
        // still carries the combined count from before that split. Both branches carry the same
        // two AIRs, so this is not a divergence to repair here: the constant feeds the split
        // probe's estimate and has to mean the same thing on both. So pin it, and assert the
        // direction that matters -- it may sit above the two AIRs together, never below.
        let estimate_per_row = tail_gkr_interactions(SyscallCode::KECCAK_PERMUTE)
            .expect("KECCAK_PERMUTE has no tail_gkr_interactions entry");
        assert_eq!(
            estimate_per_row, 280,
            "the keccak estimate is pinned at 280; changing it here alone makes probe output \
             incomparable across builds"
        );
        let (keccak_rows, _) = tail_rows_and_width(SyscallCode::KECCAK_PERMUTE)
            .expect("KECCAK_PERMUTE has no tail_rows_and_width entry");
        let real =
            measured("KeccakPermuteChip", None) * keccak_rows + measured("KeccakControlChip", None);
        let estimated = estimate_per_row * keccak_rows;
        println!("MEASURED KECCAK_PERMUTE(+control) = {real} per event (estimate {estimated})");
        assert!(
            estimated >= real,
            "tail_gkr_interactions under-counts a keccak event: estimate {estimated}, \
             KeccakPermuteChip + KeccakControlChip {real}"
        );
    }
}

#[cfg(test)]
mod tail_merge_cap_tests {
    use super::*;

    /// Finalize buckets first (the last one short), then the init stream in buckets.
    #[test]
    fn blocks_are_finalize_buckets_then_init_buckets() {
        let b = DEFERRED_MEMORY_BUCKET;
        assert_eq!(
            deferred_memory_blocks(40, 2 * b + 5),
            vec![
                (0..0, 0..b),
                (0..0, b..2 * b),
                (0..0, 2 * b..2 * b + 5),
                (0..40, 2 * b + 5..2 * b + 5),
            ]
        );
        assert_eq!(deferred_memory_blocks(0, 3), vec![(0..0, 0..3)]);
        assert_eq!(deferred_memory_blocks(7, 0), vec![(0..7, 0..0)]);
        // A large init stream (many nonzero hint words) is bucketed like finalize.
        assert_eq!(
            deferred_memory_blocks(2 * b + 5, 3),
            vec![
                (0..0, 0..3),
                (0..b, 3..3),
                (b..2 * b, 3..3),
                (2 * b..2 * b + 5, 3..3),
            ]
        );
        assert!(deferred_memory_blocks(0, 0).is_empty());
    }

    /// Cap-only replay of the packing loop in `split` over `deferred_memory_blocks` (the cells
    /// budget and the GKR line sit well above the cap for memory-only records): `(init,
    /// finalize)` events per record.
    fn plan(init: usize, finalize: usize) -> Vec<(usize, usize)> {
        let (mut out, mut cur_i, mut cur_f) = (Vec::new(), 0usize, 0usize);
        for (ir, fr) in deferred_memory_blocks(init, finalize) {
            let block = ir.len() + fr.len();
            if cur_i + cur_f > 0 && cur_i + cur_f + block >= TAIL_MERGE_MAX_MEM_EVENTS {
                out.push((cur_i, cur_f));
                cur_i = 0;
                cur_f = 0;
            }
            cur_i += ir.len();
            cur_f += fr.len();
        }
        if cur_i + cur_f > 0 {
            out.push((cur_i, cur_f));
        }
        out
    }

    /// Four buckets per record under the one 2^22 cap (a stream of 10 or 14 buckets packs as
    /// [4][4][2] or [4][4][4][2]), and the init block rides on the last record unless it would
    /// push that record to the cap.
    #[test]
    fn finalize_buckets_pack_and_init_rides_on_the_last_record() {
        let b = DEFERRED_MEMORY_BUCKET;
        // Four full buckets, a remainder and a large init stream: the remainder and the init
        // share the last record, the four buckets stand at 2^22 - 4 with no MemoryInitialize.
        assert_eq!(
            plan(1_190_000, 4 * b + 567_000),
            vec![(0, 4 * b), (1_190_000, 567_000)]
        );
        // Exactly four buckets: the init block would reach the cap and opens its own record.
        assert_eq!(plan(100, 4 * b), vec![(0, 4 * b), (100, 0)]);
        // Longer streams: more records of four buckets each, never a 2^23 record.
        assert_eq!(plan(32, 10 * b), vec![(0, 4 * b), (0, 4 * b), (32, 2 * b)]);
        assert_eq!(
            plan(32, 14 * b),
            vec![(0, 4 * b), (0, 4 * b), (0, 4 * b), (32, 2 * b)]
        );
        assert_eq!(
            plan(32, 16 * b),
            vec![(0, 4 * b), (0, 4 * b), (0, 4 * b), (0, 4 * b), (32, 0)]
        );
        // Small streams: one record.
        assert_eq!(plan(40, 1000), vec![(40, 1000)]);
        // No init at all (every touched word fresh, no registers used): no MemoryInitialize
        // anywhere.
        assert_eq!(plan(0, 2 * b + 5), vec![(0, 2 * b + 5)]);
    }
}

#[cfg(test)]
mod ga1_merge_tests {
    use super::{
        merge_precompile_local_mem_inner, precompile_local_mem, precompile_local_mem_mut,
        MemoryLocalEvent, PrecompileEvent, RvAddr, RvChunk, SyscallEvent,
    };
    use crate::{
        chips::chips::riscv_memory::event::MemoryRecord,
        emulator::riscv::{
            event_types::{RvClk, RvTimestamp, RvValue},
            syscalls::precompiles::EllipticCurveDoubleEvent,
        },
    };
    use std::collections::BTreeMap;

    type Group = Vec<(SyscallEvent, PrecompileEvent)>;

    const ADDRS: usize = 8;

    fn addr(k: usize) -> RvAddr {
        0x1000 + 8 * k as RvAddr
    }

    fn record(chunk: RvChunk, timestamp: RvTimestamp, value: RvValue) -> MemoryRecord {
        MemoryRecord {
            chunk,
            timestamp,
            value,
        }
    }

    fn entry(addr: RvAddr, initial: MemoryRecord, last: MemoryRecord) -> MemoryLocalEvent {
        MemoryLocalEvent {
            addr,
            initial_mem_access: initial,
            final_mem_access: last,
        }
    }

    /// A Secp256k1 double call: the variant with the fewest fields, everything but the
    /// local-memory table left at its default (the merge reads nothing else).
    fn double_call(
        chunk: RvChunk,
        clk: RvClk,
        entries: Vec<MemoryLocalEvent>,
    ) -> (SyscallEvent, PrecompileEvent) {
        let syscall = SyscallEvent {
            chunk,
            clk,
            ..Default::default()
        };
        let event = EllipticCurveDoubleEvent {
            chunk,
            clk,
            local_mem_access: entries,
            ..Default::default()
        };
        (syscall, PrecompileEvent::Secp256k1Double(event))
    }

    fn entries(group: &Group, i: usize) -> &[MemoryLocalEvent] {
        precompile_local_mem(&group[i].1)
    }

    fn total_entries(group: &Group) -> usize {
        group
            .iter()
            .map(|(_, pe)| precompile_local_mem(pe).len())
            .sum()
    }

    // The access records of the fixture, by address index.
    fn fresh(k: usize) -> MemoryRecord {
        record(0, 0, 100 + k as RvValue)
    }
    fn f_rec(k: usize) -> MemoryRecord {
        record(1, 11, 200 + k as RvValue)
    }
    fn g_rec(k: usize) -> MemoryRecord {
        record(1, 21, 300 + k as RvValue)
    }
    fn h_rec(k: usize) -> MemoryRecord {
        record(1, 31, 400 + k as RvValue)
    }
    /// Same value as `g_rec` with the timestamp of an access in between: not `g_rec`.
    fn x_rec(k: usize) -> MemoryRecord {
        record(1, 22, 300 + k as RvValue)
    }
    fn j_rec(k: usize) -> MemoryRecord {
        record(2, 6, 500 + k as RvValue)
    }

    /// Four calls over the same eight addresses. A, B, C sit in chunk 1 at clk 10, 20, 30; D in
    /// chunk 2 at clk 5. B continues every address of A (merge); C continues A+B on the even
    /// addresses (chained merge) and starts from a different record on the odd ones (no merge,
    /// and the kept entries interleave with the dropped ones); D continues C's finals but in
    /// another chunk (no merge).
    fn fixture() -> Group {
        let a = double_call(
            1,
            10,
            (0..ADDRS)
                .map(|k| entry(addr(k), fresh(k), f_rec(k)))
                .collect(),
        );
        let b = double_call(
            1,
            20,
            (0..ADDRS)
                .map(|k| entry(addr(k), f_rec(k), g_rec(k)))
                .collect(),
        );
        let c = double_call(
            1,
            30,
            (0..ADDRS)
                .map(|k| {
                    let initial = if k.is_multiple_of(2) {
                        g_rec(k)
                    } else {
                        x_rec(k)
                    };
                    entry(addr(k), initial, h_rec(k))
                })
                .collect(),
        );
        let d = double_call(
            2,
            5,
            (0..ADDRS)
                .map(|k| entry(addr(k), h_rec(k), j_rec(k)))
                .collect(),
        );
        vec![a, b, c, d]
    }

    /// The record's net Memory-bus multiset: every entry receives `(addr, initial)` and sends
    /// `(addr, final)`, and a send and a receive of one tuple cancel. Plain tuples as keys
    /// because `MemoryRecord` is not `Ord`.
    fn net_global_tuples(group: &Group) -> BTreeMap<(RvAddr, RvChunk, RvTimestamp, RvValue), i64> {
        let mut net = BTreeMap::new();
        for (_, pe) in group {
            for e in precompile_local_mem(pe) {
                let key = |r: MemoryRecord| (e.addr, r.chunk, r.timestamp, r.value);
                *net.entry(key(e.initial_mem_access)).or_insert(0) -= 1;
                *net.entry(key(e.final_mem_access)).or_insert(0) += 1;
            }
        }
        net.retain(|_, n| *n != 0);
        net
    }

    #[test]
    fn merges_adjacent_same_address_entries_within_one_chunk() {
        let mut group = fixture();
        assert_eq!(total_entries(&group), 4 * ADDRS);

        let merges = merge_precompile_local_mem_inner(&mut group);

        // A <- B on all eight addresses, then A <- C on the four even ones.
        assert_eq!(merges, ADDRS + ADDRS / 2);
        assert_eq!(total_entries(&group), 4 * ADDRS - merges);

        // A keeps every address in order; initial stays A's, final is the last merged call's.
        let a = entries(&group, 0);
        assert_eq!(a.len(), ADDRS);
        for (k, e) in a.iter().enumerate() {
            assert_eq!(e.addr, addr(k));
            assert_eq!(e.initial_mem_access, fresh(k));
            let expected = if k.is_multiple_of(2) {
                h_rec(k)
            } else {
                g_rec(k)
            };
            assert_eq!(e.final_mem_access, expected, "addr index {k}");
        }

        // B is absorbed entirely.
        assert!(entries(&group, 1).is_empty());

        // C keeps exactly the odd addresses, in order and untouched.
        let c = entries(&group, 2);
        assert_eq!(c.len(), ADDRS / 2);
        for (n, e) in c.iter().enumerate() {
            let k = 2 * n + 1;
            assert_eq!(e.addr, addr(k));
            assert_eq!(e.initial_mem_access, x_rec(k));
            assert_eq!(e.final_mem_access, h_rec(k));
        }

        // D matches C's finals but lives in another chunk: untouched.
        let d = entries(&group, 3);
        assert_eq!(d.len(), ADDRS);
        for (k, e) in d.iter().enumerate() {
            assert_eq!(e.addr, addr(k));
            assert_eq!(e.initial_mem_access, h_rec(k));
            assert_eq!(e.final_mem_access, j_rec(k));
        }
    }

    #[test]
    fn net_global_tuples_are_unchanged_by_the_merge() {
        let mut group = fixture();
        let before = net_global_tuples(&group);
        // Not vacuous: 8 fresh receives, 4 odd-address G sends, 4 X receives, 8 chunk-2 sends.
        assert_eq!(before.len(), ADDRS + ADDRS / 2 + ADDRS / 2 + ADDRS);

        merge_precompile_local_mem_inner(&mut group);

        assert_eq!(net_global_tuples(&group), before);
    }

    #[test]
    fn requires_full_record_equality_and_same_chunk() {
        // Same chunk and timestamp, different value: the later initial is not the earlier final.
        let mut value_off = vec![
            double_call(1, 10, vec![entry(addr(0), fresh(0), f_rec(0))]),
            double_call(
                1,
                20,
                vec![entry(addr(0), record(1, 11, f_rec(0).value + 1), g_rec(0))],
            ),
        ];
        assert_eq!(merge_precompile_local_mem_inner(&mut value_off), 0);
        assert_eq!(total_entries(&value_off), 2);
        assert_eq!(entries(&value_off, 0)[0].final_mem_access, f_rec(0));

        // Identical records but the calls sit in different emulation chunks.
        let mut chunk_off = vec![
            double_call(1, 10, vec![entry(addr(0), fresh(0), f_rec(0))]),
            double_call(2, 5, vec![entry(addr(0), f_rec(0), g_rec(0))]),
        ];
        assert_eq!(merge_precompile_local_mem_inner(&mut chunk_off), 0);
        assert_eq!(total_entries(&chunk_off), 2);

        // Different addresses never meet.
        let mut addr_off = vec![
            double_call(1, 10, vec![entry(addr(0), fresh(0), f_rec(0))]),
            double_call(1, 20, vec![entry(addr(1), f_rec(0), g_rec(0))]),
        ];
        assert_eq!(merge_precompile_local_mem_inner(&mut addr_off), 0);
        assert_eq!(total_entries(&addr_off), 2);

        let mut empty: Group = Vec::new();
        assert_eq!(merge_precompile_local_mem_inner(&mut empty), 0);
    }

    #[test]
    fn a_mismatch_reopens_the_chain_from_the_later_entry() {
        // A -> B merge; C breaks the chain; D continues C, so D merges into C, not into A.
        let mut group = vec![
            double_call(1, 10, vec![entry(addr(0), fresh(0), f_rec(0))]),
            double_call(1, 20, vec![entry(addr(0), f_rec(0), g_rec(0))]),
            double_call(1, 30, vec![entry(addr(0), x_rec(0), h_rec(0))]),
            double_call(1, 40, vec![entry(addr(0), h_rec(0), j_rec(0))]),
        ];
        assert_eq!(merge_precompile_local_mem_inner(&mut group), 2);
        assert_eq!(entries(&group, 0).len(), 1);
        assert_eq!(entries(&group, 0)[0].initial_mem_access, fresh(0));
        assert_eq!(entries(&group, 0)[0].final_mem_access, g_rec(0));
        assert!(entries(&group, 1).is_empty());
        assert_eq!(entries(&group, 2).len(), 1);
        assert_eq!(entries(&group, 2)[0].initial_mem_access, x_rec(0));
        assert_eq!(entries(&group, 2)[0].final_mem_access, j_rec(0));
        assert!(entries(&group, 3).is_empty());
    }

    #[test]
    fn entries_in_any_order_within_a_call_still_merge() {
        // A call's table is drained from a HashMap, so its entries come in no particular order.
        // Reverse B's entries: every pair still meets through the (chunk, addr) key, and A keeps
        // its own order.
        let mut group = fixture();
        precompile_local_mem_mut(&mut group[1].1).reverse();
        let merges = merge_precompile_local_mem_inner(&mut group);
        assert_eq!(merges, ADDRS + ADDRS / 2);
        assert_eq!(total_entries(&group), 4 * ADDRS - merges);
        let a = entries(&group, 0);
        assert_eq!(a.len(), ADDRS);
        for (k, e) in a.iter().enumerate() {
            assert_eq!(e.addr, addr(k));
            assert_eq!(e.initial_mem_access, fresh(k));
            let expected = if k.is_multiple_of(2) {
                h_rec(k)
            } else {
                g_rec(k)
            };
            assert_eq!(e.final_mem_access, expected, "addr index {k}");
        }
        assert!(entries(&group, 1).is_empty());
        assert_eq!(entries(&group, 2).len(), ADDRS / 2);
        assert_eq!(entries(&group, 3).len(), ADDRS);

        // The other way round: A reversed, B in address order. A's output order is A's input
        // order, reversed.
        let mut group = fixture();
        precompile_local_mem_mut(&mut group[0].1).reverse();
        let merges = merge_precompile_local_mem_inner(&mut group);
        assert_eq!(merges, ADDRS + ADDRS / 2);
        let a = entries(&group, 0);
        assert_eq!(a.len(), ADDRS);
        for (n, e) in a.iter().enumerate() {
            let k = ADDRS - 1 - n;
            assert_eq!(e.addr, addr(k));
            assert_eq!(e.initial_mem_access, fresh(k));
            let expected = if k.is_multiple_of(2) {
                h_rec(k)
            } else {
                g_rec(k)
            };
            assert_eq!(e.final_mem_access, expected, "addr index {k}");
        }
        assert!(entries(&group, 1).is_empty());
    }

    #[test]
    fn empty_calls_are_skipped() {
        // A call with no local-memory entries neither blocks a merge across it nor contributes
        // entries, wherever it sits in the group.
        let a = || {
            double_call(
                1,
                10,
                (0..ADDRS)
                    .map(|k| entry(addr(k), fresh(k), f_rec(k)))
                    .collect(),
            )
        };
        let c = |clk| {
            double_call(
                1,
                clk,
                (0..ADDRS)
                    .map(|k| entry(addr(k), f_rec(k), g_rec(k)))
                    .collect(),
            )
        };
        let empty = |clk| double_call(1, clk, Vec::new());

        let mut mid: Group = vec![a(), empty(20), c(30)];
        let before = net_global_tuples(&mid);
        assert_eq!(merge_precompile_local_mem_inner(&mut mid), ADDRS);
        assert_eq!(total_entries(&mid), ADDRS);
        assert!(entries(&mid, 1).is_empty());
        assert!(entries(&mid, 2).is_empty());
        for (k, e) in entries(&mid, 0).iter().enumerate() {
            assert_eq!(e.addr, addr(k));
            assert_eq!(e.initial_mem_access, fresh(k));
            assert_eq!(e.final_mem_access, g_rec(k));
        }
        assert_eq!(net_global_tuples(&mid), before);

        let mut first: Group = vec![empty(5), a(), c(30)];
        assert_eq!(merge_precompile_local_mem_inner(&mut first), ADDRS);
        assert_eq!(total_entries(&first), ADDRS);
        assert!(entries(&first, 0).is_empty());
        assert_eq!(entries(&first, 1).len(), ADDRS);
        assert!(entries(&first, 2).is_empty());

        let mut last: Group = vec![a(), c(30), empty(40)];
        assert_eq!(merge_precompile_local_mem_inner(&mut last), ADDRS);
        assert_eq!(total_entries(&last), ADDRS);
        assert_eq!(entries(&last, 0).len(), ADDRS);
        assert!(entries(&last, 1).is_empty());
        assert!(entries(&last, 2).is_empty());
    }
}
