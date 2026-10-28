//! MLE/WHIR-backend RISCV proving from a real ELF.
//!
//! Reuses brevis chips' `constraints.rs` via the builder adapter (no per-chip AIR
//! re-implementation). Runs the MLE debug checker (constraints + interaction/bus balance) over
//! every chunk, then proves and (on the positive path) round-trips every chunk proof through the
//! versioned codec before verifying — the only live `Proof::decode` caller, so this run exercises
//! the decode-hardening that recursion / distributed callers depend on.
//!
//! Usage:
//!   cargo run --release -p pico-vm --example test_mle_riscv -- --elf keccak --n 10 --field kb
//!
//! `keccak`, not `fib`: the forgery table has arms that only exist on a MemoryLocal entry whose
//! interval starts inside the chunk, and only a syscall splits an interval that way. fib invokes
//! no precompile, so those arms find nothing to forge and fail loudly.

use std::{
    borrow::{Borrow, BorrowMut},
    collections::BTreeMap,
    env,
    panic::AssertUnwindSafe,
    sync::Arc,
};

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::{
    codec::{Decode, Encode},
    config::riscv_params_with_100_bits_security,
    proof::Proof,
    StarkEngine,
};
use pico_vm::{
    chips::{
        chips::{
            riscv_cpu::columns::CpuCols,
            riscv_memory::{
                event::{is_fresh_local_mem_event, set_fresh_local_mem_flips, MemoryLocalEvent},
                local::columns::{MemoryLocalCols, SingleMemoryLocal},
                read_write::columns::{MemoryChipCols, MemoryChipValueCols},
            },
        },
        precompiles::keccak256::columns::KeccakMemCols,
    },
    compiler::{
        program::ProgramBehavior,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::riscv::record::EmulationRecord,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{logger::setup_logger, septic::SepticDigest},
    mle::machine::riscv::{self, RiscvProof, VerifyRiscvError},
};
use tracing::{info, warn};

#[path = "common/parse_args.rs"]
mod parse_args;

/// Negative test: forge one field of a chip's trace and require the MLE debug check to reject the
/// chunk. Panics if a forgery is accepted.
///
/// The interaction half of that check is the load-bearing one. Several of the columns below were
/// de-materialized, so their binding now lives in a lookup's multiset equality rather than in an
/// `assert_*`, and a per-chip constraint check alone would accept the forgery.
///
/// Lives in the example, not the library, so the shipping prover carries no tamper hooks.
fn reject_forged_memory_witness(program: Arc<Program>, records: &[EmulationRecord]) {
    /// Picks the field by struct field, not by column offset — a reordered layout would silently
    /// retarget an offset. One variant per row type: a MemRw row packs `MEMORY_RW_DATAPAR` slots,
    /// a Cpu row is a single `CpuCols`.
    enum Target {
        Mem(fn(&mut MemoryChipValueCols<riscv::Kb>) -> &mut riscv::Kb),
        Cpu(fn(&mut CpuCols<riscv::Kb>) -> &mut riscv::Kb),
        Local(fn(&mut SingleMemoryLocal<riscv::Kb>) -> &mut riscv::Kb),
        Keccak(fn(&mut KeccakMemCols<riscv::Kb>) -> &mut riscv::Kb),
    }
    use Target::{Cpu, Keccak, Local, Mem};

    /// Which rows an arm forges. `AllReal` covers every real row and is required for columns that
    /// are legitimately all-zero on a small workload (`pc_carry` is 1 only on the last word of a
    /// 64 KiB window); `NonZero`
    /// covers only already-set cells and is required for
    /// columns whose constraints are gated on an instruction kind, where forging an unread row would
    /// be accepted and prove nothing. `InChunk` / `Sentinel` (MemoryLocal only) select one of the
    /// two entry shapes, because the constraints that hold differ between them: forging the same
    /// column is caught algebraically on one shape and only by the buses on the other, so an arm
    /// that spanned both would not pin down which. `FirstStep` (KeccakPermute only) selects the
    /// first-step row of each real permutation, the row that exports the permutation input.
    #[derive(Clone, Copy, PartialEq)]
    enum Rows {
        AllReal,
        NonZero,
        InChunk,
        Sentinel,
        FirstStep,
    }
    use Rows::{AllReal, FirstStep, InChunk, NonZero, Sentinel};

    let engine: riscv::Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, false);
    let (pk, _) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let chips = RiscvChipType::<riscv::Kb>::all_chips();

    // (name, target, which rows, delta). `delta` is 1 unless the arm's comment says why a larger
    // step is needed.
    for (what, target, rows, delta) in [
        ("MemRw timestamp (clk)", Mem(|c| &mut c.clk), AllReal, 1u32),
        (
            "MemRw address (addr_word[0])",
            Mem(|c| &mut c.addr_word[0]),
            AllReal,
            1,
        ),
        // The stack guard `addr_limb1_inv * addr_word[1] == is_mem` holds only for the honest
        // inverse, and every real access has `addr_word[1] != 0` (guest addresses sit above the
        // register space), so the arm has real rows to land on in any workload.
        (
            "MemRw stack guard inverse (addr_limb1_inv)",
            Mem(|c| &mut c.addr_limb1_inv),
            AllReal,
            1,
        ),
        // The limb selector is not a committed column (it is the product of the two offset bits),
        // so what a wrong selection has to get past is the ungated degree-3 definition of
        // `selected_limb`; every workload has real rows for it.
        (
            "MemRw selected limb",
            Mem(|c| &mut c.selected_limb),
            AllReal,
            1,
        ),
        // `shift` is defined ungated on every row (`is_sh*(a0 - sel) +
        // is_sb*increment`); only SB/SH rows carry a non-zero value, so `NonZero` keeps the arm
        // on rows where the definition actually reads something.
        ("MemRw store shift", Mem(|c| &mut c.shift), NonZero, 1),
        // SB, LB and LBU rows split the selected memory limb into `mem_limb_low_byte` and an
        // affine high byte, pinned by one shared U8Range lookup. A forged low byte first breaks
        // the row's algebraic use of it (the `selected_byte` definition on LB/LBU, the `shift`
        // definition on SB) and would otherwise push the affine high byte out of the lookup.
        (
            "MemRw memory limb low byte (mem_limb_low_byte)",
            Mem(|c| &mut c.mem_limb_low_byte),
            NonZero,
            1,
        ),
        // `lhw_val` is pinned by a gated definition on LH (selected limb), LW/LWU (high half)
        // and LB (`256 * selected_byte`) rows, so a forged value fails that definition before
        // the U16MSB lookup sees it.
        (
            "MemRw U16MSB operand (lhw_val)",
            Mem(|c| &mut c.lhw_val),
            NonZero,
            1,
        ),
        (
            "MemRw ts diff low limb (diff_16bit_limb)",
            Mem(|c| &mut c.memory_access.access.diff_16bit_limb),
            AllReal,
            1,
        ),
        (
            "MemRw ts diff high limb (diff_hi9)",
            Mem(|c| &mut c.memory_access.access.diff_hi9),
            AllReal,
            1,
        ),
        // `opcode` is gone and the dispatch message carries the flag-weighted sum instead. A real row
        // has exactly one variant flag set, so bumping any one flag on every real row changes that sum
        // whether the flag was the set one or not — no particular instruction needs to be present.
        (
            "MemRw opcode flag (instruction.is_ld)",
            Mem(|c| &mut c.instruction.is_ld),
            AllReal,
            1,
        ),
        // One `clk` column, bounded by the row chain (N2 on every edge, the start value on row
        // 0) and carried by the register, memory and Ecall messages.
        ("Cpu clk", Cpu(|c| &mut c.clk), AllReal, 1),
        // `a_eq_b` is gone; equality is now `1 - a_lt_b - a_gt_b`, which is the equality indicator
        // only because both are boolean and mutually exclusive; what carries those two properties
        // is the merged CMP dispatch to the Lt chip. These arms are caught algebraically, through
        // the taken predicate that gates the branch target equation and through that dispatch.
        (
            "Cpu comparison bit (a_lt_b)",
            Cpu(|c| &mut c.a_lt_b),
            NonZero,
            1,
        ),
        (
            "Cpu comparison bit (a_gt_b)",
            Cpu(|c| &mut c.a_gt_b),
            NonZero,
            1,
        ),
        // `is_last` is defined by the row chain: `is_real - next.is_real` on transition rows and
        // `is_real` on the last row (`eval_row_chain`, N4 / N5). The harness tampers additively.
        // The AllReal arm sets the column to 1 on every real row before the sink, where N4 wants
        // 0, and to 2 on the sink; the NonZero arm touches only the sink and pushes it to 2,
        // which N4 (or N5, when the sink is the last physical row) rejects. Clearing the sink or
        // moving it to another row is not expressible here; the parity test's
        // `marks == [n_events - 1]` assertion covers the placement instead.
        (
            "Cpu chain sink (is_last)",
            Cpu(|c| &mut c.is_last),
            AllReal,
            1,
        ),
        (
            "Cpu chain sink (is_last), nonzero rows",
            Cpu(|c| &mut c.is_last),
            NonZero,
            1,
        ),
        // `pc_carry` has no constraint of its own: the Program message carries it, so every real
        // row's value is pinned to the preprocessed table's `[pc[0] >= 0xFFFC]` and any bump
        // puts the tuple off the table (LogUp). A jump row writing a real return address also
        // reads it in the three `pc + 4 = op_a` limb equations, which this whole-AIR run fails
        // first. `reject_pc_carry_off_table` below isolates the lookup on a non-jump row.
        ("Cpu pc carry", Cpu(|c| &mut c.pc_carry), AllReal, 1),
        // `num_extra_clk` feeds the row chain's clk step (`next.clk = clk + 4 + num_extra_clk`,
        // `eval_row_chain` N2) and is certified by the Ecall chip against byte 2 of the syscall
        // code; it is also what the chain's integer clk bound rests on, through the Ecall chip's
        // BitRange(6) lookup. A one-row tamper is caught by the Ecall equality and by N2 on the
        // edge to the successor; the BitRange bound is what rules out a *consistent* large
        // value, which no single-cell tamper can produce.
        (
            "Cpu extra clk (num_extra_clk)",
            Cpu(|c| &mut c.num_extra_clk),
            NonZero,
            100,
        ),
        // Neither `prev_chunk`, `compare_clk` nor `prev_clk` is a column: what binds an access to
        // its predecessor is the pair
        // of difference limbs, from which the AIR defines `prev_clk = clk - (diff16 + hi9 * 2^16)
        // - 1` for the regional bus — against a sentinel that MemoryLocalChip has to agree with.
        // Forging a limb moves the derived predecessor clk off the bus; no algebraic guard reads
        // it, so the rejection comes from the bus (and from the Byte table for a limb pushed out
        // of range).
        (
            "Cpu ts diff low limb (op_a_access)",
            Cpu(|c| &mut c.op_a_access.access.diff_16bit_limb),
            AllReal,
            1,
        ),
        (
            "Cpu ts diff high limb (op_b_access)",
            Cpu(|c| &mut c.op_b_access.access.diff_hi9),
            AllReal,
            1,
        ),
        // `op_b`/`op_c` immediates are preprocessed as two low limbs plus a sign bit, and the
        // operand word's limbs 2 and 3 are pinned to `0xFFFF * sign` on immediate rows. A bumped
        // limb 3 is rejected there on a branch or immediate-c row (a negative immediate makes it
        // non-zero) and by the memory bus on a register row; a bumped limb 2 on every real row is
        // rejected by the same equation on JAL/LUI-style immediate-b rows and by the bus elsewhere.
        (
            "Cpu op_c value limb 3 (sign fill)",
            Cpu(|c| &mut c.op_c_access.access.value[3]),
            NonZero,
            1,
        ),
        (
            "Cpu op_b value limb 2",
            Cpu(|c| &mut c.op_b_access.access.value[2]),
            AllReal,
            1,
        ),
        // `next_pc`'s own range check is gone: on a row with a real successor the row chain pins
        // it limb by limb to that row's `pc` (`eval_row_chain`, N1), and the branch/JAL targets
        // are field equations rather than ALU dispatches. Both limbs, since a pc is the two low
        // limbs. A tamper here fails N1 on every edge with a real successor (`eval_pc` and the
        // public-value hand-off reject it as well; N1 is not the only guard).
        //
        // Since X12 `pc` has no range check of its own either: what captures it is the Program
        // lookup, whose message carries both limbs and whose count is exactly `is_real`, so
        // every real row's limbs are pinned element by element to a preprocessed table row. The
        // `Cpu pc limb 0` arm below bumps limb 0 by 4, which is a legitimate program address --
        // but it does not get to exercise that: the harness forges EVERY real row, row 0
        // included, so the first thing to fail is `PV.start_pc == row 0's pc`. All it shows is
        // that a uniform pc shift is caught, and the arm is kept for that. The forgery that
        // isolates the Program lookup is `reject_pc_limb_shift`, which has to move the row chain
        // in step with the pc to get there.
        (
            "Cpu next_pc limb 0",
            Cpu(|c| &mut c.next_pc.0[0]),
            AllReal,
            4,
        ),
        (
            "Cpu next_pc limb 1",
            Cpu(|c| &mut c.next_pc.0[1]),
            AllReal,
            1,
        ),
        ("Cpu pc limb 0", Cpu(|c| &mut c.pc.0[0]), AllReal, 4),
        // `op_c_access`'s value is what the ALU dispatch sends as the third operand. On a row the
        // transpiler re-encoded from AUIPC it has to equal that row's own pc, which
        // `when(imm_c).assert_word_eq(op_c_val, instruction.op_c)` gets from the Program table;
        // elsewhere it is the register read the memory bus pins.
        (
            "Cpu op_c value limb 0",
            Cpu(|c| &mut c.op_c_access.access.value[0]),
            AllReal,
            1,
        ),
        // The ALU dispatch multiplicity, which since X12 also gates the rows that used to be
        // AUIPC (the separate `is_auipc_not_x0` column is gone). Caught by its definitional
        // constraint `is_alu_not_x0 == is_alu_instruction * (1 - op_a_0)`.
        (
            "Cpu ALU dispatch multiplicity",
            Cpu(|c| &mut c.is_alu_not_x0),
            AllReal,
            1,
        ),
        // MemRw range-checks `addr_word[1]` in-chip (U16Range). This arm does not reach that
        // lookup: the stack guard `addr_limb1_inv * addr[1] == is_mem` holds only for the honest
        // limb, so it rejects the forgery first.
        (
            "MemRw address (addr_word[1])",
            Mem(|c| &mut c.addr_word[1]),
            AllReal,
            1,
        ),
        // MemoryLocal's new columns. The shape flag and the normalized clk decide which `clk` an
        // entry puts on the regional bus; the clk-gap limbs back the `initial_clk < final_clk`
        // check on the in-chunk shape.
        (
            "MemLocal shape flag (initial_in_chunk)",
            Local(|c| &mut c.initial_in_chunk),
            AllReal,
            1,
        ),
        (
            "MemLocal regional clk (initial_clk_regional)",
            Local(|c| &mut c.initial_clk_regional),
            AllReal,
            1,
        ),
        // Both limbs of the in-chunk clk gap, so a change that silently narrowed this check from
        // 25 bits to 16 (dropping the `hi9 * 2^16` term) cannot pass.
        (
            "MemLocal clk gap (clk_diff_16bit_limb)",
            Local(|c| &mut c.clk_diff_16bit_limb),
            InChunk,
            1,
        ),
        (
            "MemLocal clk gap (clk_diff_hi9)",
            Local(|c| &mut c.clk_diff_hi9),
            InChunk,
            1,
        ),
        // A MemoryLocal entry's address and final-value limbs carry no range check of their
        // own: the regional memory bus pins them to the accessing chip's tuple, so a forged limb
        // has no peer and the LogUp sum stops balancing. Both arms land on every real entry.
        (
            "MemLocal address limb 2 (bus-bound)",
            Local(|c| &mut c.addr[2]),
            AllReal,
            1,
        ),
        (
            "MemLocal final value limb 3 (bus-bound)",
            Local(|c| &mut c.final_value[3]),
            AllReal,
            1,
        ),
        // `final_clk` carries a different burden on each shape, so it gets one arm per shape.
        // On a sentinel entry the clk-gap check is gated off and nothing in the chip constrains
        // it -- it is held in place purely by the two buses it appears on, which makes it the
        // cheapest lever a future change could turn into a real hole. On an in-chunk entry the
        // gap decomposition catches it without the buses.
        (
            "MemLocal final clk (sentinel shape, bus-only)",
            Local(|c| &mut c.final_clk),
            Sentinel,
            1,
        ),
        (
            "MemLocal final clk (in-chunk shape)",
            Local(|c| &mut c.final_clk),
            InChunk,
            1,
        ),
        // The permutation input goes onto the state bus from the first step, gated by
        // `export_in = step_flags[0] * is_real`; any other value of the flag fails that definition.
        (
            "Keccak input export flag (export_in)",
            Keccak(|c| &mut c.export_in),
            NonZero,
            1,
        ),
        // The exported input is the first step's `a`, which theta_4 ties limb by limb to the bit
        // columns; a forged limb on the first-step row breaks that limb equation.
        (
            "Keccak first-step input limb (a[0][0][0])",
            Keccak(|c| &mut c.keccak.a[0][0][0]),
            FirstStep,
            1,
        ),
    ] {
        let air_id = match target {
            Mem(_) => riscv::air_id::MEM_RW,
            Cpu(_) => riscv::air_id::CPU,
            Local(_) => riscv::air_id::MEM_LOCAL,
            Keccak(_) => riscv::air_id_for("KeccakPermute").expect("KeccakPermute air id"),
        };
        // Padding rows are all-zero and carry no lookup multiplicity, so forging them proves nothing;
        // every arm has to land on real rows. Realness is read per chip rather than inferred from the
        // target column being nonzero — which is what the old two-arm version did, and what a
        // uniformly-zero column makes impossible:
        //  - Cpu has `is_real`.
        //  - MemRw has no such column, but `addr_limb1_inv` exists precisely to constrain every
        //    real access to lie above the register space, i.e. `addr_word[1] != 0`, so that limb
        //    is non-zero on exactly the real rows.
        //
        // Which chunk populates a column is a property of the workload, not of the chip: an
        // in-chunk MemoryLocal entry needs a syscall to split an interval, and the chunk that has
        // one is not necessarily the first. So scan for the first record that populates the target
        // rather than pinning chunk 0, which would make an arm silently workload-dependent.
        let mut tampered = None;
        for record in records {
            let mut ctx = riscv::build_ctx(&chips, record, false);
            {
                // A record without this chip (a precompile-only or memory chunk) has nothing
                // to forge; the scan moves on to the next record.
                let Some((_, air)) = ctx.per_trace.iter_mut().find(|(id, _)| *id == air_id) else {
                    continue;
                };
                let width = air.common_main.width;
                let mut forged = 0usize;
                let mut forge = |cell: &mut riscv::Kb, live: bool| {
                    if live {
                        *cell += riscv::Kb::from_u32(delta);
                        forged += 1;
                    }
                };
                for row in air.common_main.values.chunks_mut(width) {
                    match target {
                        Mem(pick) => {
                            let cols: &mut MemoryChipCols<riscv::Kb> = row.borrow_mut();
                            for slot in cols.values.iter_mut() {
                                let real = slot.addr_word[1] != riscv::Kb::ZERO;
                                let cell = pick(slot);
                                let live = match rows {
                                    AllReal => real,
                                    NonZero => *cell != riscv::Kb::ZERO,
                                    InChunk | Sentinel | FirstStep => {
                                        panic!("{what}: shape selectors are chip-specific")
                                    }
                                };
                                forge(cell, live);
                            }
                        }
                        Cpu(pick) => {
                            let cols: &mut CpuCols<riscv::Kb> = row.borrow_mut();
                            let real = cols.is_real != riscv::Kb::ZERO;
                            let cell = pick(cols);
                            let live = match rows {
                                AllReal => real,
                                NonZero => *cell != riscv::Kb::ZERO,
                                InChunk | Sentinel | FirstStep => {
                                    panic!("{what}: shape selectors are chip-specific")
                                }
                            };
                            forge(cell, live);
                        }
                        Keccak(pick) => {
                            let cols: &mut KeccakMemCols<riscv::Kb> = row.borrow_mut();
                            let real = cols.is_real != riscv::Kb::ZERO;
                            let first_step = cols.keccak.step_flags[0] != riscv::Kb::ZERO;
                            let cell = pick(cols);
                            let live = match rows {
                                AllReal => real,
                                NonZero => *cell != riscv::Kb::ZERO,
                                FirstStep => real && first_step,
                                InChunk | Sentinel => {
                                    panic!("{what}: shape selectors are MemoryLocal-only")
                                }
                            };
                            forge(cell, live);
                        }
                        Local(pick) => {
                            let cols: &mut MemoryLocalCols<riscv::Kb> = row.borrow_mut();
                            for slot in cols.memory_local_entries.iter_mut() {
                                let real = slot.is_real != riscv::Kb::ZERO;
                                let in_chunk = slot.initial_in_chunk != riscv::Kb::ZERO;
                                let cell = pick(slot);
                                let live = match rows {
                                    AllReal => real,
                                    NonZero => *cell != riscv::Kb::ZERO,
                                    InChunk => real && in_chunk,
                                    Sentinel => real && !in_chunk,
                                    FirstStep => {
                                        panic!("{what}: FirstStep is KeccakPermute-only")
                                    }
                                };
                                forge(cell, live);
                            }
                        }
                    }
                }
                if forged == 0 {
                    continue;
                }
                tampered = Some((forged, ctx));
            }
            break;
        }
        // An arm that forges nothing would pass without testing anything, which is the failure mode
        // that matters most for a table this long. It means the target moved or no chunk of this
        // workload populates it — either way the arm is not doing its job and has to say so. The
        // `InChunk` arms need a workload that invokes a precompile.
        let (forged, ctx) = tampered.unwrap_or_else(|| {
            let hint = if rows == InChunk {
                " — this arm needs a workload that invokes a precompile, e.g. --elf keccak"
            } else {
                ""
            };
            panic!(
                "no {what} cell to forge in any of the {} record(s){hint}",
                records.len()
            )
        });

        // The debug check panics on a violation; silence the hook so the expected failure does not
        // print a backtrace, then restore it.
        let ctx = riscv::ctx_to_engine(ctx);
        let hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let rejected =
            std::panic::catch_unwind(AssertUnwindSafe(|| engine.debug_with_pk(&airs, &ctx, &pk)))
                .is_err();
        std::panic::set_hook(hook);

        assert!(
            rejected,
            "forged {what} was ACCEPTED by the MLE debug check — the binding is not sound"
        );
        info!("forged {what} rejected ({forged} rows) ✓");
    }
}

/// Negative test for the *encoding* of `pc`, not its value: move `2^16` from limb 1 into limb 0,
/// over a run of rows chosen so that the Program lookup is the only thing left that can reject it.
///
/// `pc.reduce() = pc[0] + pc[1]·2^16` is invariant under the move, so every
/// polynomial constraint that reads a pc as a *number* still holds. What must reject the chunk is
/// the LogUp half of the debug check.
///
/// **Why a run, and not a single row.** A one-row shift is not evidence about the Program lookup,
/// because the row chain catches it first: on every edge with a real successor the rotation
/// constraint N1 (`riscv_cpu/constraints.rs`, `eval_row_chain`) pins the successor's `pc` limb
/// by limb to this row's `next_pc`, so shifting one row's `pc` alone fails N1 on the edge into
/// it. The debug checker runs the constraints before `check_logup`, so a one-row forgery would be
/// rejected as a constraint violation and never reach the lookup, and the deleted range check's
/// replacement would stay unproven.
///
/// So the forgery moves the row chain along with the pc. Over a run of consecutive ordinary
/// sequential rows `k..=m`, shift `pc` on rows `k..=m` AND `next_pc` on rows `k-1..=m-1`. Every
/// chain edge then has both of its endpoints shifted identically, so N1 holds limb by limb on
/// every edge; `reduce()` is unchanged on both columns of every touched row, so
/// `next_pc == pc + 4` still holds on all of them, including the two boundary rows where only one
/// of the two columns moved. What is left off-table is the Program lookup's tuple on rows
/// `k..=m`: its count is exactly `is_real` and its receiving side reads only preprocessed columns,
/// so each real row's `pc` limbs are pinned element by element to a row of a table built as
/// `Pc::try_from(pc_base + 4i)` (`riscv_program/traces.rs`) -- canonical 16-bit limbs. A limb 0
/// of `pc[0] + 2^16 >= 2^16` is in no row of that table. That is the sense in which the Program
/// lookup is *strictly stronger* than the deleted `slice_range_check_u16(&local.pc.0,
/// local.is_real)`: the range check only bounded the limbs, this pins them to a real instruction
/// address, and it is the only guard the forgery below has to get past.
///
/// The run is restricted to rows that are real, carry no class selector at all (so: the derived
/// ALU class -- which is also where a re-encoded AUIPC row lands), and are neither the halt row
/// nor the chain sink. That is what keeps every other element-wise reader of the two columns out
/// of the way:
///
/// * row 0's `pc` is pinned to `PV.start_pc` by `when_first_row().assert_pc_eq`
///   (`riscv_cpu/public_values/constraints.rs`), so no `pc` below row 1 is ever touched -- the
///   run's first shifted `pc` is row `k >= 1`. (Row `k-1` may be row 0; only its `next_pc` moves,
///   and nothing constrains that element-wise.)
/// * a jump row with a real return address relates the limbs of `pc + 4` to `op_a`'s through
///   `Pc::add_limb_with_carry` (`riscv_cpu/jump/constraints.rs`);
/// * a JALR row's `next_pc` limbs feed the in-chip target carry chain (same file);
/// * a halt row has `next_pc == 0` (`riscv_cpu/ecall/constraints.rs`);
/// * the `is_last` row hands its `next_pc` to `PV.next_pc`.
///
/// Each of those would fail a constraint, or a second bus, before the Program lookup was reached.
///
/// It cannot be an arm of the tamper table above: that harness is a single-field mutator by
/// construction (`Cpu(fn(&mut CpuCols<F>) -> &mut F)`), and this forgery moves four fields across
/// two rows in lockstep.
fn reject_pc_limb_shift(program: Arc<Program>, records: &[EmulationRecord]) {
    let engine: riscv::Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, false);
    let (pk, _) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let chips = RiscvChipType::<riscv::Kb>::all_chips();

    // Cap on the run length. Two rows is already the whole argument (one shifted `pc`, one
    // chain edge); a few more only make the stdout diagnostic more convincing without making it
    // unreadable.
    const MAX_RUN: usize = 4;

    let zero = riscv::Kb::ZERO;
    // Which chunk has a forgeable run is a property of the workload, so scan rather than pinning
    // chunk 0 (the same reason the table above scans).
    let mut tampered = None;
    for record in records {
        let mut ctx = riscv::build_ctx(&chips, record, false);
        {
            let (_, air) = ctx
                .per_trace
                .iter_mut()
                .find(|(id, _)| *id == riscv::air_id::CPU)
                .expect("no Cpu trace to tamper");
            let width = air.common_main.width;

            // Pass 1: classify. An "ordinary sequential" row is real, has no class selector set
            // (the derived ALU class), is not the halt row and is not the chain sink -- see the
            // doc comment for why each exclusion is needed.
            let ordinary: Vec<bool> = air
                .common_main
                .values
                .chunks(width)
                .map(|row| {
                    let cols: &CpuCols<riscv::Kb> = row.borrow();
                    let s = &cols.opcode_selector;
                    let no_class = s.is_ecall == zero
                        && s.is_memory == zero
                        && s.is_store == zero
                        && s.is_beq == zero
                        && s.is_bne == zero
                        && s.is_blt == zero
                        && s.is_bge == zero
                        && s.is_bltu == zero
                        && s.is_bgeu == zero
                        && s.is_jal == zero
                        && s.is_jalr == zero;
                    cols.is_real != zero && no_class && cols.is_halt == zero && cols.is_last == zero
                })
                .collect();

            // The window is `first..=last`: `next_pc` moves on `first..last`, `pc` on
            // `first+1..=last`. Two rows is the minimum (one chain edge, one shifted `pc`).
            let Some(first) =
                (0..ordinary.len().saturating_sub(1)).find(|&i| ordinary[i] && ordinary[i + 1])
            else {
                continue;
            };
            let mut last = first + 1;
            while last + 1 < ordinary.len() && ordinary[last + 1] && last - first + 1 < MAX_RUN {
                last += 1;
            }

            // Pass 2: forge. `reduce()` is invariant under `(+2^16, -1)` on limbs (0, 1).
            let shift = riscv::Kb::from_u32(1 << 16);
            for (i, row) in air.common_main.values.chunks_mut(width).enumerate() {
                if i < first || i > last {
                    continue;
                }
                let cols: &mut CpuCols<riscv::Kb> = row.borrow_mut();
                if i > first {
                    cols.pc.0[0] += shift;
                    cols.pc.0[1] -= riscv::Kb::ONE;
                }
                if i < last {
                    cols.next_pc.0[0] += shift;
                    cols.next_pc.0[1] -= riscv::Kb::ONE;
                }
            }
            tampered = Some((first, last, ctx));
        }
        break;
    }
    // No forgeable run means the arm silently tested nothing — the failure mode that matters most
    // for a negative test. Say so instead.
    let (first, last, ctx) = tampered.unwrap_or_else(|| {
        panic!(
            "no forgeable Cpu run (two or more consecutive real rows with no class selector, no \
             halt and no chain sink) in any of the {} record(s)",
            records.len()
        )
    });

    // The debug check panics on a violation; silence the hook so the expected failure does not
    // print a backtrace, then restore it. `check_logup` still prints the offending bus tuples on
    // stdout, which is the useful half of the diagnostic.
    let ctx = riscv::ctx_to_engine(ctx);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome =
        std::panic::catch_unwind(AssertUnwindSafe(|| engine.debug_with_pk(&airs, &ctx, &pk)));
    std::panic::set_hook(hook);

    let payload = outcome.err().unwrap_or_else(|| {
        panic!(
            "a pc limb shift on Cpu rows {first}..={last} was ACCEPTED by the MLE debug check — \
             dropping the pc U16 range check left the limb decomposition unbound"
        )
    });
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    // Not just "rejected": rejected by the multiset equality. The debug checker runs every AIR's
    // constraints first and only then `check_logup`, so a constraint panic here would mean the
    // window picked up a row whose limbs an algebraic guard reads — the exclusions above are what
    // keep those out — and the arm would be measuring that guard rather than the lookup.
    assert!(
        msg.contains("LogUp multiset equality check failed"),
        "pc limb shift on Cpu rows {first}..={last} was rejected, but by a constraint rather than \
         by the multiset equality: {msg:?}"
    );
    info!("forged Cpu pc limb shift (rows {first}..={last}) rejected by the LogUp check ✓");
}

/// Negative test for the jump-row return address. There the register file's u16-limb invariant
/// rests on the carry witness `pc_carry` being the Program table's `[pc[0] >= 0xFFFC]`: the
/// Program message carries it (`riscv_cpu/constraints.rs`, `looking_program`) and nothing
/// range-checks the return
/// address `pc + 4` (`riscv_cpu/register/constraints.rs`); every other written word is canonical
/// by construction. The one forgery that satisfies every algebraic constraint of a jump row is to
/// flip the carry witness from 0 to 1 while moving limb 0 down by `2^16` (which wraps below zero
/// in the field) and limb 1 up by 1: `carry * 2^16 = pc[0] + 4 - op_a[0]` and
/// `op_a[1] = pc[1] + carry` both still hold. Only lookups can reject it -- the Program lookup,
/// whose tuple now carries a carry the table does not hold for this pc, and the memory bus, whose
/// written value moved -- so the rejection must come from the LogUp check.
fn reject_jump_return_carry_shift(program: Arc<Program>, records: &[EmulationRecord]) {
    let engine: riscv::Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, false);
    let (pk, _) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let chips = RiscvChipType::<riscv::Kb>::all_chips();

    let zero = riscv::Kb::ZERO;
    let mut tampered = None;
    for record in records {
        let mut ctx = riscv::build_ctx(&chips, record, false);
        let forged = {
            let (_, air) = ctx
                .per_trace
                .iter_mut()
                .find(|(id, _)| *id == riscv::air_id::CPU)
                .expect("no Cpu trace to tamper");
            let width = air.common_main.width;
            let mut hit = None;
            for (i, row) in air.common_main.values.chunks_mut(width).enumerate() {
                let cols: &mut CpuCols<riscv::Kb> = row.borrow_mut();
                let s = &cols.opcode_selector;
                let is_jump = s.is_jal != zero || s.is_jalr != zero;
                if cols.is_real != zero
                    && is_jump
                    && cols.instruction.op_a_0 == zero
                    && cols.pc_carry == zero
                {
                    cols.pc_carry += riscv::Kb::ONE;
                    cols.op_a_access.access.value.0[0] -= riscv::Kb::from_u32(1 << 16);
                    cols.op_a_access.access.value.0[1] += riscv::Kb::ONE;
                    hit = Some(i);
                    break;
                }
            }
            hit
        };
        if let Some(row) = forged {
            tampered = Some((row, ctx));
            break;
        }
    }
    let (row, ctx) = tampered.unwrap_or_else(|| {
        panic!(
            "no jump row with rd != x0 and carry 0 in any of the {} record(s)",
            records.len()
        )
    });

    let ctx = riscv::ctx_to_engine(ctx);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome =
        std::panic::catch_unwind(AssertUnwindSafe(|| engine.debug_with_pk(&airs, &ctx, &pk)));
    std::panic::set_hook(hook);

    let payload = outcome.err().unwrap_or_else(|| {
        panic!(
            "a return-address carry shift on Cpu row {row} was ACCEPTED by the MLE debug check — \
             the Program lookup does not pin the jump-row carry"
        )
    });
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(
        msg.contains("LogUp multiset equality check failed"),
        "return-address carry shift on Cpu row {row} was rejected, but by a constraint rather \
         than by the multiset equality: {msg:?}"
    );
    info!("forged jump return-address carry shift (Cpu row {row}) rejected by the LogUp check ✓");
}

/// Negative test for the JALR target's low bit. `jalr_lsb` is pinned by membership, not by a
/// range check: the successor's `pc` must equal this row's `next_pc` limb by limb
/// (`eval_row_chain`, N1) and its
/// Program lookup ties that pc to a table row, so of the two witnesses `(lsb = 0, S)` and
/// `(lsb = 1, S - 1)` that reproduce the low limb `S` of the in-chip sum `b + c` only one matches
/// (`riscv_cpu/jump/constraints.rs`). Slide a JALR row to the other witness -- `next_pc[0] - 1`
/// with `lsb = 1`, which keeps `next_pc[0] + lsb`, and so every carry expression, unchanged --
/// and require a rejection.
/// With the row chain written as rotation constraints the first thing to fail is N1 on the edge
/// into the (unchanged) successor, so this arm checks fail-closed behaviour, not which guard
/// fires. Rows whose `next_pc` goes to the public values instead (`is_last`) are skipped: there
/// the rejection would come from the PV equality, which is not the mechanism under test.
fn reject_jalr_lsb_slide(program: Arc<Program>, records: &[EmulationRecord]) {
    let engine: riscv::Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, false);
    let (pk, _) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let chips = RiscvChipType::<riscv::Kb>::all_chips();

    let zero = riscv::Kb::ZERO;
    let mut tampered = None;
    for record in records {
        let mut ctx = riscv::build_ctx(&chips, record, false);
        let forged = {
            let (_, air) = ctx
                .per_trace
                .iter_mut()
                .find(|(id, _)| *id == riscv::air_id::CPU)
                .expect("no Cpu trace to tamper");
            let width = air.common_main.width;
            let mut hit = None;
            for (i, row) in air.common_main.values.chunks_mut(width).enumerate() {
                let cols: &mut CpuCols<riscv::Kb> = row.borrow_mut();
                if cols.is_real != zero
                    && cols.opcode_selector.is_jalr != zero
                    && cols.jalr_lsb == zero
                    && cols.is_last == zero
                {
                    cols.next_pc.0[0] -= riscv::Kb::ONE;
                    cols.jalr_lsb += riscv::Kb::ONE;
                    hit = Some(i);
                    break;
                }
            }
            hit
        };
        if let Some(row) = forged {
            tampered = Some((row, ctx));
            break;
        }
    }
    let (row, ctx) = tampered.unwrap_or_else(|| {
        panic!(
            "no non-final JALR row with lsb 0 in any of the {} record(s)",
            records.len()
        )
    });

    let ctx = riscv::ctx_to_engine(ctx);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome =
        std::panic::catch_unwind(AssertUnwindSafe(|| engine.debug_with_pk(&airs, &ctx, &pk)));
    std::panic::set_hook(hook);

    let payload = outcome.err().unwrap_or_else(|| {
        panic!(
            "a jalr lsb slide on Cpu row {row} was ACCEPTED by the MLE debug check — membership \
             does not pin the unmasked target's low bit"
        )
    });
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    let head: String = msg.chars().take(96).collect();
    info!("forged jalr lsb slide (Cpu row {row}) rejected ✓ ({head:?})");
}

/// Negative test for the Program-table pinning of `pc_carry`. The column has no constraint of
/// its own: a jump row with a real return address reads it in `pc + 4 = op_a`
/// (`riscv_cpu/jump/constraints.rs`), and on every other row the only thing that holds it is the
/// Program lookup, whose message ends with it (`riscv_cpu/constraints.rs`, `looking_program`) and
/// whose receiving side reads the preprocessed `[pc[0] >= 0xFFFC]` (`riscv_program/columns.rs`).
/// Bump `pc_carry` on one real **non-jump** row: no polynomial constraint reads the cell there,
/// so the rejection must come from the LogUp check, and that is asserted -- a constraint panic
/// would mean the arm landed on a row some algebraic guard reads and was measuring that guard
/// rather than the lookup. The table-driven `Cpu pc carry` arm above only asserts "rejected";
/// this is the arm that shows the lookup alone does it.
fn reject_pc_carry_off_table(program: Arc<Program>, records: &[EmulationRecord]) {
    let engine: riscv::Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        riscv::log_stacked_height_from_env(),
    ));
    let airs = riscv::mle_riscv_air_refs(program, false);
    let (pk, _) = engine.keygen_with_app_prep(&airs, riscv::RISCV_APP_PREP_AIR_IDS);
    let chips = RiscvChipType::<riscv::Kb>::all_chips();

    let zero = riscv::Kb::ZERO;
    let mut tampered = None;
    for record in records {
        let mut ctx = riscv::build_ctx(&chips, record, false);
        let forged = {
            let (_, air) = ctx
                .per_trace
                .iter_mut()
                .find(|(id, _)| *id == riscv::air_id::CPU)
                .expect("no Cpu trace to tamper");
            let width = air.common_main.width;
            let mut hit = None;
            for (i, row) in air.common_main.values.chunks_mut(width).enumerate() {
                let cols: &mut CpuCols<riscv::Kb> = row.borrow_mut();
                let s = &cols.opcode_selector;
                let is_jump = s.is_jal != zero || s.is_jalr != zero;
                if cols.is_real != zero && !is_jump {
                    cols.pc_carry += riscv::Kb::ONE;
                    hit = Some(i);
                    break;
                }
            }
            hit
        };
        if let Some(row) = forged {
            tampered = Some((row, ctx));
            break;
        }
    }
    let (row, ctx) = tampered.unwrap_or_else(|| {
        panic!(
            "no real non-jump Cpu row in any of the {} record(s)",
            records.len()
        )
    });

    let ctx = riscv::ctx_to_engine(ctx);
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome =
        std::panic::catch_unwind(AssertUnwindSafe(|| engine.debug_with_pk(&airs, &ctx, &pk)));
    std::panic::set_hook(hook);

    let payload = outcome.err().unwrap_or_else(|| {
        panic!(
            "a pc_carry bump on non-jump Cpu row {row} was ACCEPTED by the MLE debug check — \
             the Program lookup does not pin the carry column"
        )
    });
    let msg = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_default();
    assert!(
        msg.contains("LogUp multiset equality check failed"),
        "pc_carry bump on non-jump Cpu row {row} was rejected, but by a constraint rather than \
         by the multiset equality: {msg:?}"
    );
    info!("forged pc_carry on non-jump Cpu row {row} rejected by the LogUp check ✓");
}

/// Negative-test hook: bump the value of one MemoryFinalize event (`addr >= 0x1000`, clear of the
/// x0 row the chip pins) in one record. Every trace of that record is built from its events, so
/// the chunk stays internally consistent and its proof valid; but the Global receive its
/// MemoryFinalize row now carries matches no send from the chunk that produced the word's final
/// state, so `Σ gcs != 0`. Finalize only: a zero-initial main-memory word has no MemoryInitialize
/// event (`riscv_memory/event.rs`), so a matching init/final pair is not there to bump. Lives in
/// the example, not the library, so the shipping driver stays env-free.
fn corrupt_cross_chunk_memory(records: &mut [EmulationRecord]) {
    for rec in records.iter_mut() {
        if let Some(e) = rec
            .memory_finalize_events
            .iter_mut()
            .find(|e| e.addr >= 0x1000)
        {
            e.value = e.value.wrapping_add(1);
            warn!(
                "CORRUPT_MEMORY: tampered finalize value at addr={:#x}",
                e.addr
            );
            return;
        }
    }
    // No tamperable cell ⇒ the negative test would otherwise run on untampered records and the
    // gcs==0 assertion would pass, falsely reporting success. Fail loudly instead.
    panic!("CORRUPT_MEMORY: no finalize event found to tamper; negative test could not run");
}

/// Fresh-verdict negative tests: invert the fresh verdict of one first-touch MemoryLocal entry
/// and require the cross-chunk GCS check to reject. A fresh entry (`is_fresh_local_mem`: a
/// main-memory word
/// outside the image that starts at zero) declares its initial state on the AIR instead of
/// receiving it from the Global bus (`has_initial = 0`). The hook inverts that verdict for one
/// address, and every consumer -- trace generation, the extra-record pass, the event counters,
/// the GPU staging -- regenerates from the inverted verdict, so each chunk's proof stays
/// self-consistent and only the cross-chunk sum can catch it:
///
/// - an image word's first touch declared fresh: the vk digest's send for it has no receiver;
/// - a fresh entry declared inherited: it receives `(0, 0, addr, 0)` that nothing sent.
///
/// The hook is installed after emulation (the records are already there, so the emulator's own
/// use of the predicate is not affected) and cleared before the verdict is checked, so a panic
/// inside leaves nothing behind for the next arm. Runs unconditionally, like the forgery arms
/// above: the validation chain's `negative` step sets no environment.
fn reject_fresh_verdict_flip(
    program: Arc<Program>,
    records: &[EmulationRecord],
    what: &str,
    pick: impl Fn(&MemoryLocalEvent, &BTreeMap<u64, u64>) -> bool,
) {
    let image: &BTreeMap<u64, u64> = &program.memory_image;
    let addr = records
        .iter()
        .flat_map(|r| r.get_local_mem_events())
        .find(|e| pick(e, image))
        .map(|e| e.addr)
        .unwrap_or_else(|| panic!("no {what} in any of the {} record(s)", records.len()));

    set_fresh_local_mem_flips(&[addr]);
    let proved = std::panic::catch_unwind(AssertUnwindSafe(|| {
        riscv::prove_riscv(
            program.clone(),
            records,
            riscv::log_stacked_height_from_env(),
            bucket_shapes(),
        )
    }));
    set_fresh_local_mem_flips(&[]);
    let bundle = proved
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
        .expect("riscv prove");

    let outcome = riscv::verify_riscv(
        &bundle,
        bundle.vk.pre_hash,
        &[(
            riscv::air_id::PROGRAM,
            riscv::riscv_program_commit(&bundle.vk),
        )],
        program.initial_global_cumulative_sum(),
    );
    match outcome {
        Err(VerifyRiscvError::CrossChunkMemoryInconsistency) => {
            info!(
                "{what} at {addr:#x} with its fresh verdict inverted rejected by the cross-chunk \
                 GCS check ✓"
            );
        }
        Err(other) => panic!(
            "{what} at {addr:#x} with its fresh verdict inverted was rejected, but per chunk \
             rather than by the cross-chunk sum: {other}"
        ),
        Ok(()) => panic!(
            "{what} at {addr:#x} with its fresh verdict inverted was ACCEPTED: the Global \
             multiset does not bind the entry's initial state"
        ),
    }
}

/// Arm (a): the first touch of an image word declared fresh. The word's image value has to be
/// zero -- with a nonzero one the inverted entry would trip G4 (a declaring entry's initial
/// value is pinned to zero) inside its chunk, which is not the check under test. BSS words are
/// in the image as zeros, so a program that touches any zero-initialized static has one.
fn reject_image_first_touch_declared_fresh(program: Arc<Program>, records: &[EmulationRecord]) {
    reject_fresh_verdict_flip(
        program,
        records,
        "first-touch entry of a zero-valued image word",
        |e, image| {
            let initial = &e.initial_mem_access;
            initial.chunk == 0
                && initial.timestamp == 0
                && initial.value == 0
                && e.addr >= 0x100
                && image.contains_key(&e.addr)
        },
    );
}

/// Arm (b): a fresh entry declared inherited.
fn reject_fresh_entry_declared_inherited(program: Arc<Program>, records: &[EmulationRecord]) {
    reject_fresh_verdict_flip(program, records, "fresh entry", |e, image| {
        is_fresh_local_mem_event(e, image)
    });
}

/// Whether to prove under the whitelist's coarse-bucket shapes, read off `VK_VERIFICATION` the
/// way `test_mle_e2e` reads it. Off (the default) is the natural-height path this example has
/// always taken; on, every chunk carries the canonical presence set, which is the only way the
/// debug checker below sees an all-padding trace for a chip the chunk raised no events for.
fn bucket_shapes() -> bool {
    env::var("VK_VERIFICATION")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Negative-test path (env-gated): prove then verify with the honest vk but tampered inputs, so the
/// cross-chunk GCS check must reject. `CORRUPT_MEMORY` tampers `records` before proving;
/// `SKIP_INITIAL_GCS` passes a zero initial GCS (→ the cross-chunk sum no longer cancels). A correct
/// backend panics on `verify_riscv`'s typed error; reaching the end means the check failed to fire.
fn run_negative_test(program: Arc<Program>, records: &[EmulationRecord]) {
    let tampered;
    let records: &[EmulationRecord] = if env::var("CORRUPT_MEMORY").is_ok() {
        let mut r = records.to_vec();
        corrupt_cross_chunk_memory(&mut r);
        tampered = r;
        &tampered
    } else {
        records
    };

    let bundle = riscv::prove_riscv(
        program.clone(),
        records,
        riscv::log_stacked_height_from_env(),
        bucket_shapes(),
    )
    .expect("riscv prove");

    let initial_gcs: SepticDigest<riscv::Kb> = if env::var("SKIP_INITIAL_GCS").is_ok() {
        warn!("SKIP_INITIAL_GCS set: omitting initial GCS (negative test)");
        SepticDigest::zero()
    } else {
        program.initial_global_cumulative_sum()
    };

    riscv::verify_riscv(
        &bundle,
        bundle.vk.pre_hash,
        &[(
            riscv::air_id::PROGRAM,
            riscv::riscv_program_commit(&bundle.vk),
        )],
        initial_gcs,
    )
    .expect("cross-chunk verification failed");
    info!("negative-test path completed without the expected failure");
}

fn main() {
    setup_logger();
    // The GPU riscv prover allocates from the shared pool; a CPU build has none to set up.
    #[cfg(feature = "cuda")]
    riscv::init_mle_gpu_pool(riscv::MLE_GPU_DEVICE);
    let (elf, stdin, args) = parse_args::parse_args::<KoalaBearPoseidon2>();
    // kb-only by design: the MLE backend ships only a KoalaBear engine
    // (`KoalaBearPoseidon2CpuEngine`); no other field is vendored.
    assert_eq!(
        args.field, "kb",
        "test_mle_riscv is KoalaBear-only by design (the MLE backend has no other engine); \
         got --field {}",
        args.field
    );

    let compiler = Compiler::new(SourceType::RISCV, elf).expect("failed to parse ELF");
    let program = compiler.compile();

    let records = riscv::emulate(program.clone(), stdin, None);
    info!("emulated {} chunk(s)", records.len());

    // 22 covers the default chunk, which `emulate` clamps to the 2^22 event buffers. Raising
    // `CHUNK_SIZE` past that needs this raised with it.
    riscv::debug_records(program.clone(), &records, 22, false);
    info!("all chunks passed MLE debug (constraints + interactions) ✓");

    // The mirror image of the check above: a forged memory witness must be REJECTED.
    reject_forged_memory_witness(program.clone(), &records);
    reject_pc_limb_shift(program.clone(), &records);
    reject_jump_return_carry_shift(program.clone(), &records);
    reject_jalr_lsb_slide(program.clone(), &records);
    reject_pc_carry_off_table(program.clone(), &records);

    // The fresh-verdict arms prove the whole run twice more: their rejection is a cross-chunk
    // one, which only the GCS sum over real proofs can show.
    reject_image_first_touch_declared_fresh(program.clone(), &records);
    reject_fresh_entry_declared_inherited(program.clone(), &records);

    // The CORRUPT_MEMORY / SKIP_INITIAL_GCS negative-test env hooks live in this driver (not the
    // library), so those runs still fail loudly (a correct backend panics on the typed verify error).
    if env::var("CORRUPT_MEMORY").is_ok() || env::var("SKIP_INITIAL_GCS").is_ok() {
        run_negative_test(program, &records);
        return;
    }

    // Positive path: prove → serialize → deserialize → verify, so the full versioned-codec round
    // trip (decode-hardening) runs on every invocation.
    let bundle = riscv::prove_riscv(
        program.clone(),
        &records,
        riscv::log_stacked_height_from_env(),
        bucket_shapes(),
    )
    .expect("riscv prove");
    info!(
        "proved {} chunk(s) on the MLE/WHIR backend",
        bundle.chunk_proofs.len()
    );

    let chunk_proofs: Vec<Proof<riscv::Sc>> = bundle
        .chunk_proofs
        .iter()
        .map(|proof| {
            let bytes = proof.encode_to_vec().expect("encode chunk proof");
            Proof::decode_from_bytes(&bytes).expect("decode chunk proof")
        })
        .collect();
    let bundle = RiscvProof {
        vk: bundle.vk,
        chunk_proofs,
    };
    info!("round-tripped all chunk proofs through the versioned codec ✓");

    // Test convenience: trusted values taken from the bundle's own keygen (the lean pre-hash
    // covers machine+shape only, so the program commitment is pinned explicitly alongside).
    let expected_vk_pre_hash = bundle.vk.pre_hash;
    let expected_program_commit = riscv::riscv_program_commit(&bundle.vk);
    let initial_gcs = program.initial_global_cumulative_sum();
    riscv::verify_riscv(
        &bundle,
        expected_vk_pre_hash,
        &[(riscv::air_id::PROGRAM, expected_program_commit)],
        initial_gcs,
    )
    .expect("verify_riscv failed");
    info!("all chunks verified on the MLE/WHIR backend ✓");
}
