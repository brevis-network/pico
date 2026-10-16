use super::{
    columns::CpuCols,
    instruction::columns::InstructionCols,
    opcode_selector::columns::{OpcodeSelectorCols, OPCODE_SELECTORS_COL_MAP},
    CpuChip,
};
use crate::{
    compiler::{addr::Pc, word::Word},
    emulator::riscv::public_values::PublicValues,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, ScopedBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::RISCV_NUM_PVS,
};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use std::{array, borrow::Borrow, iter::once};

impl<F: PrimeField32, CB: ChipBuilder<F> + ScopedBuilder> Air<CB> for CpuChip<F>
where
    CB::Var: Sized,
{
    #[inline(never)]
    fn eval(&self, builder: &mut CB) {
        // The chip reads its own row and the next one. The row chain (`eval_row_chain`) is
        // written as rotation constraints on `next`, so keygen sees `max_rotation == 1` and
        // marks the chip `need_rot`: every column is opened at two points and the convert
        // program reads the matching hints. Nothing else in the chip reads `next`.
        let main = builder.main();
        let local = main.current_slice();
        let local: &CpuCols<CB::Var> = (*local).borrow();
        let next = main.next_slice();
        let next: &CpuCols<CB::Var> = (*next).borrow();

        let public_values_slice: [CB::Expr; RISCV_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_slice.as_slice().borrow();

        // Contrain the interaction with program table.
        self.looking_program(
            builder,
            local.pc,
            local.instruction,
            local.opcode_selector,
            local.pc_carry,
            local.is_real,
        );

        // Neither `pc` nor `next_pc` carries a range check of its own, and `pc_carry` has no
        // constraint of its own.
        //
        // `pc`: the Program lookup just above is stronger than a range check. Its count is
        // exactly `is_real`, and the receiving side reads only preprocessed columns, so on every
        // real row the whole tuple -- both `pc` limbs and `pc_carry` included -- equals some row
        // of the preprocessed table element by element. That table is built as
        // `Pc::try_from(pc_base + 4i)` with `pc_carry = [pc[0] >= 0xFFFC]`
        // (`riscv_program/traces.rs`), whose limbs are canonical 16-bit values, so the limbs are
        // not merely in `[0, 2^16)`: they are a real instruction address, and the carry out of
        // `pc[0] + 4` is a function of it. `Pc::add_limb_with_carry` range-checks nothing, so in
        // isolation the `pc + 4` carry decomposition would admit a limb shifted by `2^16`; its
        // only caller here is `jump/constraints.rs` (`pc + 4 = op_a`), and with the `pc` limbs
        // and `pc_carry` pinned by the table that decomposition is unique
        // (`register/constraints.rs` spells out the four limbs).
        //
        // `next_pc`: on a row with a real successor the row chain pins it limb by limb to the
        // successor's `pc` (`eval_row_chain`, N1), where the argument above applies; a halt row
        // has `next_pc == 0`; the last real row's becomes PV.next_pc, which the recursion chain
        // pins to the next chunk's row-0 `pc` or to zero.
        //
        // Load-bearing for the above, do not remove without redoing this argument: the Program
        // lookup's count staying exactly `is_real` (plus `is_real` being boolean), the
        // preprocessed table's `Pc::try_from(pc_base + 4i)` / `[pc[0] >= 0xFFFC]` construction,
        // and `pc_carry` travelling in the Program message.
        //
        // A fourth consumer lives in another crate and so is the one most likely to be broken
        // silently: the MLE recursion circuit proves a CPU chunk's `start_pc != 0` by summing the
        // three PV limbs and inverting the sum (the `has_cpu` branch at
        // `vm/src/mle/compiler/recursion/lowering.rs:1255-1285`). That is an "is the pc zero"
        // test only because the limbs are canonical, and they are canonical by exactly this
        // argument: `PV.start_pc`'s low two limbs are pinned limb by limb to row 0's `pc` and its
        // third limb to zero (`public_values/constraints.rs`, `when_first_row()`; row 0 is
        // forced real by `eval_is_real` below), and the Program lookup then pins that row to a
        // preprocessed row whose limbs are canonical by construction. Weakening either hop
        // silently weakens that circuit.

        // Compute some flags for which type of instruction we are dealing with.
        let is_memory_instruction: CB::Expr =
            self.is_memory_instruction::<CB>(&local.opcode_selector);
        let is_branch_instruction: CB::Expr =
            self.is_branch_instruction::<CB>(&local.opcode_selector);
        let is_alu_instruction: CB::Expr = self.is_alu_instruction::<CB>(local);

        // Register constraints.
        builder.enter_scope("eval_registers");
        self.eval_registers::<CB>(
            builder,
            local,
            public_values.execution_chunk.clone(),
            is_branch_instruction.clone(),
        );
        builder.exit_scope();

        // Memory instructions.
        // The per-variant flags are reconstructed and self-proven on the
        // MemoryReadWriteChip side; the dispatch message carries `is_memory`.
        //
        // The message also carries the chunk and `clk` (base clk, no position offset)
        // so the MemoryReadWriteChip's timestamp is bound by this lookup to the Cpu chip's
        // program-order chunk/clk. `clk` is an integer below the row-chain bound (see
        // `eval_chunk_clk`). The chunk element is the proof's `execution_chunk` public value
        // itself, not a committed column: the recursion chain keeps `execution_chunk <= chunk`
        // and the convert circuit range-checks `chunk`, and the receiving chip's `chunk` column
        // is pinned to the value by this lookup. Message width 17. The `clk` element is the
        // committed `clk` column, read through `clk_expr`.
        let clk_expr = Self::clk_expr::<CB>(local);
        let values = once(local.instruction.opcode)
            .chain(local.op_a_val())
            .chain(local.op_b_val())
            .chain(local.op_c_val())
            .chain(once(local.instruction.op_a_0))
            .chain(once(local.opcode_selector.is_memory))
            .map(Into::into)
            .chain(once(public_values.execution_chunk.clone()))
            .chain(once(clk_expr));
        // Memory lookup
        builder.looking(SymbolicLookup::new(
            values.collect(),
            is_memory_instruction,
            LookupType::Memory,
            LookupScope::Regional,
        ));

        // ALU instructions.
        //
        // Skip the dispatch when the destination is `x0`. The register file pins
        // `op_a_val()` to zero in that case (`register/constraints.rs`), so dispatching
        // would ask the ALU chip for `(opcode, 0, b, c)` while the chip supplies
        // `(opcode, b op c, b, c)` -- an imbalance for any instruction whose result is
        // non-zero. The emulator correspondingly stops emitting the event (`mode.rs`).
        // `op_a_0` comes from the preprocessed program table, so it cannot be lied about.
        builder.assert_eq(
            local.is_alu_not_x0,
            is_alu_instruction * (CB::Expr::ONE - local.instruction.op_a_0),
        );
        builder.looking_alu(
            local.instruction.opcode,
            local.op_a_val(),
            local.op_b_val(),
            local.op_c_val(),
            local.is_alu_not_x0,
        );

        // Branch instructions.
        builder.enter_scope("eval_branch_ops");
        self.eval_branch_ops::<CB>(builder, is_branch_instruction.clone(), local);
        builder.exit_scope();

        // Jump instructions.
        builder.enter_scope("eval_jump_ops");
        self.eval_jump_ops::<CB>(builder, local);
        builder.exit_scope();

        // ECALL instruction: is_halt gating + the fat lookup to the Ecall chip, which owns the
        // syscall decode, the syscall-table send and the ecall-driven public-value constraints.
        builder.enter_scope("eval_ecall");
        self.eval_ecall(builder, local, public_values.execution_chunk.clone());
        builder.exit_scope();

        // HALT ecall and UNIMPL instruction.
        builder.enter_scope("eval_halt_unimpl");
        self.eval_halt_unimpl(builder, local);
        builder.exit_scope();

        // Check that the chunk and clk is updated correctly.
        builder.enter_scope("eval_chunk_clk");
        self.eval_chunk_clk(builder, local);
        builder.exit_scope();

        // Check that the pc is updated correctly.
        builder.enter_scope("eval_pc");
        self.eval_pc(builder, local);
        builder.exit_scope();

        // Check public values constraints.
        // Check public values constraints.
        builder.enter_scope("eval_public_values");
        self.eval_public_values(builder, local, public_values);
        builder.exit_scope();

        // Check that the is_real flag is correct.
        builder.enter_scope("eval_is_real");
        self.eval_is_real(builder, local);
        builder.exit_scope();

        // Link this row to its successor: pc and clk hand-off, real-row prefix, `is_last`.
        builder.enter_scope("eval_row_chain");
        self.eval_row_chain(builder, local, next);
        builder.exit_scope();

        // UNIMP / EBREAK are unsatisfiable, not merely chunk-ending: the emulator aborts on both.
        // There is no `is_unimpl` selector. The Program table writes row 0 in place of every trap
        // instruction (`riscv_program/traces.rs`), so no table row carries a trap's pc and a row
        // that claims one finds no receiver on the Program lookup. (A trap row kept in the table
        // without the selector would make `unimp` a no-op: `op_a = x0` suppresses the ALU
        // dispatch.)

        // Check that when `is_real=0` that all flags that send interactions are zero.
        builder.enter_scope("opcode_selector_checks");
        local
            .opcode_selector
            .into_iter()
            .enumerate()
            .for_each(|(i, selector)| {
                if i == OPCODE_SELECTORS_COL_MAP.imm_b {
                    builder
                        .when(CB::Expr::ONE - local.is_real)
                        .assert_one(local.opcode_selector.imm_b);
                } else if i == OPCODE_SELECTORS_COL_MAP.imm_c {
                    builder
                        .when(CB::Expr::ONE - local.is_real)
                        .assert_one(local.opcode_selector.imm_c);
                } else {
                    builder
                        .when(CB::Expr::ONE - local.is_real)
                        .assert_zero(selector);
                }
            });
        builder.exit_scope();
    }
}

impl<F: Field> CpuChip<F> {
    /// The row's `clk`, as an expression.
    ///
    /// One committed column, not range-checked: the row chain bounds it as an integer
    /// (`eval_chunk_clk`). Every reader goes through this accessor.
    pub(crate) fn clk_expr<CB: ChipBuilder<F>>(local: &CpuCols<CB::Var>) -> CB::Expr {
        local.clk.into()
    }

    /// Whether the instruction is an ALU instruction (derived, not committed).
    ///
    /// The instruction class is a one-hot partition over real rows, backed by the Program-table
    /// lookup (every non-ALU class selector is pinned to the program's value for the row's pc).
    /// ALU is therefore the exact complement, and it is zero on padding rows because `is_real`
    /// is zero there while every class selector is also zero.
    ///
    /// The partition lost its `is_auipc` term in X12: the transpiler re-encodes AUIPC as a
    /// two-immediate ADD, so no compiled program reaches this chip with that opcode. If one ever
    /// did -- a hand-built `Program`, or a new encoding path -- it is fail-closed, not
    /// under-constrained, and it is worth being precise about which guard fires:
    ///
    /// * With an honest trace and `rd != x0`, the *definitional* constraint below is what fails,
    ///   before any bus is consulted. `OpcodeSelectorCols::populate` sets no class selector for
    ///   AUIPC, so this expression reads `is_real - 0 = 1`, while `traces.rs` writes
    ///   `is_alu_not_x0 = is_alu_instruction() * (op_a != 0)` and `Instruction::is_alu_instruction`
    ///   does not list AUIPC -- so the trace holds 0 where
    ///   `is_alu_instruction * (1 - op_a_0)` evaluates to 1.
    /// * A prover that repairs that by writing `is_alu_not_x0 = 1` then dispatches
    ///   `(AUIPC, ...)` on the Alu bus, which no ALU chip receives: the regional sum does not
    ///   balance and the proof is rejected. That is the malicious branch, not the honest one.
    /// * `auipc x0, imm` passes on both sides, correctly: `op_a_0 = 1` makes both the trace value
    ///   and the expression 0, nothing is dispatched, `op_a_val()` is pinned to zero by
    ///   `register/constraints.rs` and `eval_pc` advances the pc by 4 -- which is exactly the
    ///   semantics of discarding the result.
    pub(crate) fn is_alu_instruction<CB: ChipBuilder<F>>(
        &self,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        let s = &local.opcode_selector;
        // `is_branch_instruction` is already an `Expr`, so the running sum is an `Expr` and each
        // `+ Var` term stays well-typed (Expr + Var).
        let other_classes =
            self.is_branch_instruction::<CB>(s) + s.is_ecall + s.is_memory + s.is_jal + s.is_jalr;
        let is_real: CB::Expr = local.is_real.into();
        is_real - other_classes
    }

    /// Computes whether the opcode is a memory instruction.
    pub(crate) fn is_memory_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_memory.into()
    }

    /// Computes whether the opcode is a store instruction.
    pub(crate) fn is_store_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_store.into()
    }

    /// Constraints related to the pc.
    ///
    /// Verifies that the pc advances by 4 on every real row that is not a taken branch, a jump
    /// or a halt. The hand-off to the successor's `pc` is the rotation constraint N1 in
    /// `eval_row_chain`, not here.
    pub(crate) fn eval_pc<CB: ChipBuilder<F> + ScopedBuilder>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        // `next_pc == pc + 4` on every real row that is neither a taken branch, a jump nor a
        // halt: sequential rows and branch-not-taken rows share one equation. The gate
        // `is_real - taken - is_jal - is_jalr - is_halt` is 1 exactly there and 0 on taken
        // branches, jumps, halts and padding rows (selectors, the taken predicate and `is_halt`
        // are all zero off real rows). The predicate is degree 2 now that it is an expression
        // rather than a column, so this constraint is degree 3.
        //
        // A pc fits in two limbs (the guest's address space is 1.875 GiB), so `reduce()` is the
        // integer value and `+ 4` cannot leave `[0, p)` -- one field equation, no carry witness.
        // `pc_carry` stays for the jump rows, whose `pc + 4` lands in a register Word that can
        // reach past `p`.
        let advances_by_four: CB::Expr = local.is_real
            - Self::branch_taken_expr::<CB>(local)
            - local.opcode_selector.is_jal
            - local.opcode_selector.is_jalr
            - local.is_halt;
        builder.when(advances_by_four).assert_eq(
            local.next_pc.reduce::<CB>(),
            local.pc.reduce::<CB>() + CB::Expr::from_u8(4),
        );
    }

    /// Constraints related to the is_real column.
    ///
    /// This method checks that the is_real column is a boolean and that the first row is real.
    /// Monotonicity (`is_real` never comes back on across a transition) is N3 in
    /// `eval_row_chain`; together the three make the real rows a physical prefix `0..m-1` with
    /// `m >= 1`, which is the shape the row chain and the `is_last` definition rest on.
    pub(crate) fn eval_is_real<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        builder.assert_bool(local.is_real);
        builder.when_first_row().assert_one(local.is_real);
    }

    /// The class taken-predicate of a branch row, written in the comparison bits that the CMP
    /// lookup pins (`a_eq_b = 1 - a_lt_b - a_gt_b` by trichotomy):
    ///
    /// ```text
    /// BEQ: a_eq_b    BNE: a_lt_b + a_gt_b    BLT/BLTU: a_lt_b    BGE/BGEU: 1 - a_lt_b
    /// ```
    ///
    /// Every term carries a branch selector, so the expression is zero off branch rows. It used
    /// to be committed as the `branching` column and pinned by one definitional constraint; the
    /// column was given up to keep the chip at what was then 70 columns when `is_last` arrived
    /// (68 since X12), and the two consumers (`eval_pc` here and the branch target equation) now
    /// inline it. Degree 2, and the shared sub-expression is interned once in the constraint DAG.
    pub(crate) fn branch_taken_expr<CB: ChipBuilder<F>>(local: &CpuCols<CB::Var>) -> CB::Expr {
        let a_eq_b = || CB::Expr::ONE - local.a_lt_b - local.a_gt_b;
        local.opcode_selector.is_beq * a_eq_b()
            + local.opcode_selector.is_bne * (local.a_lt_b + local.a_gt_b)
            + (local.opcode_selector.is_blt + local.opcode_selector.is_bltu) * local.a_lt_b
            + (local.opcode_selector.is_bge + local.opcode_selector.is_bgeu)
                * (CB::Expr::ONE - local.a_lt_b)
    }

    /// Links each row to its successor with rotation constraints on the next row.
    ///
    /// Write `r_i` for `is_real` on row `i`, `h` for the height and `s_i = 4 + num_extra_clk_i`
    /// for the clk step. On transition rows (every row but the physically last one):
    ///
    /// * N1: `next.pc[k] = next_pc[k]` for both limbs, gated on `next.is_real`;
    /// * N2: `next.clk = clk + 4 + num_extra_clk`, gated on `next.is_real`;
    /// * N3: `is_real = 0  =>  next.is_real = 0`;
    /// * N4: `is_last = is_real - next.is_real`;
    ///
    /// and on the last row
    ///
    /// * N5: `is_last = is_real`.
    ///
    /// Why this is the whole chain argument:
    ///
    /// * Prefix. Row 0 is real (`eval_is_real`) and N3 forbids a padding row from being followed
    ///   by a real one, so `r_i = [i < m]` for some `m >= 1`. N3 is a transition constraint, so
    ///   the wrap-around edge from the last row to row 0 is unconstrained and `m = h` is legal.
    /// * One chain. Inside the prefix N1 / N2 give `(pc_{i+1}, clk_{i+1}) = (next_pc_i, clk_i +
    ///   s_i)` row by row, so the real rows form exactly one chain and it starts at row 0, whose
    ///   `pc` and `clk` are pinned to `PV.start_pc` and `CHUNK_CLK_START`. There is no multiset
    ///   to balance and no cycle to rule out.
    /// * `is_last`. On a transition row N4 reads the pattern `(r_i, r_{i+1})` as `(1,1) -> 0`,
    ///   `(1,0) -> 1`, `(0,0) -> 0` (`(0,1)` is excluded by N3); on the last row N5 reads
    ///   `is_real`. So `is_last` is 1 on row `m - 1` and 0 everywhere else: boolean, zero off
    ///   real rows and set on exactly one row, with no constraint of its own for any of the
    ///   three. `eval_public_values` and `eval_halt_unimpl` read it. Splitting the definition
    ///   across the two row selectors relies on `is_transition + is_last_row == 1` on every
    ///   evaluator: the prover builds its selectors that way
    ///   (`mle-core/src/prover/logup_zerocheck/mod.rs`), the verifier defines
    ///   `is_transition = 1 - is_last_row` (`mle-core/src/verifier/evaluator.rs`), and the debug
    ///   checker (`mle-core/src/air/debug/check_constraints.rs`), the GPU evaluator
    ///   (`zerocheck_round0.cu`) and the recursion circuit (`recursion/builder_mle.rs`) agree.
    /// * clk bound. `clk_0 = 4` (`eval_chunk_clk`) and `s_i <= 67` (`num_extra_clk` is zero off
    ///   ecall rows and below 64 on them, by the Ecall chip's BitRange(6)), so by induction along
    ///   the prefix `clk_i <= 4 + (2^MAX_RISCV_LOG_STACKED_HEIGHT - 1) * 67 < p` as an integer,
    ///   with no wrap-around. That is the bound `CLK_BOUND_FITS` checks and
    ///   `eval_memory_access_timestamp` needs.
    ///
    /// Degrees: N1 and N2 are `IsTransition * next.is_real * linear` and N3 is
    /// `IsTransition * (1 - is_real) * next.is_real` (3, the chip's maximum); N4 and N5 are 2.
    /// Reading `next` makes this a rotation AIR (keygen derives `need_rot` from the
    /// constraints); there is no new column, no new event and no change to trace generation,
    /// which already lays the real rows out as a prefix and writes `is_last` on the last one.
    pub(crate) fn eval_row_chain<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        // N1: the successor's pc is this row's `next_pc`, limb by limb.
        for (successor_pc, next_pc) in next.pc.0.iter().zip(local.next_pc.0.iter()) {
            builder
                .when_transition()
                .when(next.is_real)
                .assert_eq(*successor_pc, *next_pc);
        }

        // N2: the successor's clk is this row's clk plus the step `4 + num_extra_clk`.
        let successor_clk = Self::clk_expr::<CB>(local)
            + CB::Expr::from_u8(4)
            + self.get_num_extra_ecall_cycles::<CB>(local);
        builder
            .when_transition()
            .when(next.is_real)
            .assert_eq(Self::clk_expr::<CB>(next), successor_clk);

        // N3: real rows are a prefix (no padding -> real transition). Written with `when` on
        // `1 - is_real` rather than `when_not`, which is a `ChipBaseBuilder` method and is not in
        // scope on the filtered builder here; the constraint is the same.
        builder
            .when_transition()
            .when(CB::Expr::ONE - local.is_real)
            .assert_zero(next.is_real);

        // N4 / N5: `is_last` is the end of the prefix. On a transition row it is the drop in
        // `is_real`; on the last physical row it is `is_real` itself. The two cases are written
        // separately because `next` wraps around to row 0 on the last row.
        builder
            .when_transition()
            .assert_eq(local.is_last, local.is_real - next.is_real);
        builder
            .when_last_row()
            .assert_eq(local.is_last, local.is_real);
    }

    /// Sending end of the Program lookup. The message is `pc(2) ++ [opcode] ++
    /// InstructionCols(9) ++ OpcodeSelectorCols(13) ++ [pc_carry]`, 26 elements, mirrored by
    /// `riscv_program/constraints.rs` (`looked_program`). The trailing `pc_carry` is what pins
    /// the jump-row carry witness to the table's `[pc[0] >= 0xFFFC]`.
    fn looking_program<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        pc: Pc<CB::Var>,
        instruction: InstructionCols<impl Into<CB::Expr> + Copy>,
        selectors: OpcodeSelectorCols<impl Into<CB::Expr> + Copy>,
        pc_carry: impl Into<CB::Expr>,
        multiplicity: impl Into<CB::Expr>,
    ) {
        let values: Vec<CB::Expr> = pc
            .into_iter()
            .map(|x| x.into())
            .chain(std::iter::once(instruction.opcode.into()))
            .chain(instruction.into_iter().map(|x| x.into()))
            .chain(selectors.into_iter().map(|x| x.into()))
            .chain(std::iter::once(pc_carry.into()))
            .collect();

        // Program lookup
        builder.looking(SymbolicLookup::new(
            values,
            multiplicity.into(),
            LookupType::Program,
            LookupScope::Regional,
        ));
    }
}
