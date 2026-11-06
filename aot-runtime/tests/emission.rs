//! The AOT core's records against the interpreter's, on programs small enough to say what each
//! instruction is there for. Every `_no_count` helper the code generator calls runs here as the
//! generated code calls it, and every path the generator writes out inline (jumps, branches,
//! `ECALL`, the ALU and word forms on immediates) runs as a copy of what it writes, kept in step
//! with `instruction_translator.rs` by hand; and every program runs through the fallback
//! interpreter too, as the bootstrap stub's code runs it. The record of the one chunk each program
//! runs has to match the interpreter's in every field the emulator writes.

use std::sync::Arc;

use pico_aot_runtime::{AotEmulatorCore, AotProgram};
use pico_vm::{
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            chunk_split::ChunkSplitConfig,
            history_view::unaligned_len,
            memory::ContiguousRiscvMemory,
            public_values_compat::encode_public_value_pc_limbs,
            record::EmulationRecord,
            record_digest::field_digests,
            record_slots::hold_records_unbounded,
            riscv_emulator::{AbnormalTermination, EmulationError, TerminationReason},
        },
        stdin::EmulatorStdin,
    },
    mle::machine::{riscv::emulate_with_opts, shape::MLE_MEMORY_UNALIGNED_LOG_HEIGHT},
};

const PC_BASE: u64 = 0x1000;
/// Data at or above `MIN_SEGMENT_ADDR`: an access below it ends the run.
const DATA: u64 = 0x2_0000;

/// The rows of `field_digests` the emulator writes while it runs: not the public values, of which
/// the emulator writes only the chunk's boundary and the digest words, compared on their own, nor
/// the events the chips derive later.
const WRITTEN: [&str; 3] = ["history", "add_events", "cpu_local_memory_chain"];

fn r(opcode: Opcode, rd: u8, rs1: u64, rs2: u64) -> Instruction {
    Instruction::new(opcode, rd, rs1, rs2, false, false)
}

fn i(opcode: Opcode, rd: u8, rs1: u64, imm: i64) -> Instruction {
    Instruction::new(opcode, rd, rs1, imm as u64, false, true)
}

/// `value` stored at `base + imm`: the value register is operand `a`, the base `b`.
fn s(opcode: Opcode, value: u8, base: u64, imm: i64) -> Instruction {
    Instruction::new(opcode, value, base, imm as u64, false, true)
}

/// A program at `PC_BASE` that runs `body` and halts: `a0 = 0`, then `HALT`. (A jump to pc 0 no
/// longer halts; it ends the run abnormally.)
fn program(mut body: Vec<Instruction>) -> Arc<Program> {
    body.push(i(Opcode::ADD, 10, 0, 0));
    body.extend(syscall(0));
    Arc::new(Program::new(body, PC_BASE, PC_BASE))
}

/// `b`'s offset is in bytes, as `op_c` carries it.
fn b(opcode: Opcode, rs1: u8, rs2: u64, offset: i64) -> Instruction {
    Instruction::new(opcode, rs1, rs2, offset as u64, false, true)
}

/// Every branch, taken and not, one comparing a register with itself, and the jumps.
fn control_flow() -> Vec<Instruction> {
    use Opcode::*;
    vec![
        i(ADD, 1, 0, 5),
        i(ADD, 2, 0, -5),
        b(BEQ, 1, 1, 8),
        i(ADD, 3, 0, 1),
        b(BNE, 1, 2, 8),
        i(ADD, 3, 0, 2),
        b(BLT, 2, 1, 8),
        i(ADD, 3, 0, 3),
        b(BGE, 2, 1, 8),
        b(BLTU, 1, 2, 8),
        i(ADD, 3, 0, 4),
        b(BGEU, 1, 2, 8),
        Instruction::new(JAL, 4, 8, 0, true, true),
        i(ADD, 3, 0, 5),
        i(ADD, 5, 0, (PC_BASE + 4 * 17) as i64),
        i(JALR, 6, 5, 1),
        i(ADD, 3, 0, 6),
        r(ADD, 7, 4, 6),
    ]
}

/// `t0`, the syscall number, and `ECALL`.
fn syscall(code: u64) -> [Instruction; 2] {
    [
        i(Opcode::ADD, 5, 0, code as i64),
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
    ]
}

/// An unconstrained region: what it writes, to registers and memory, is rolled back at its exit,
/// and its exiting `ECALL`'s event goes out with the entering one's accesses. Then `HALT`.
fn unconstrained() -> Arc<Program> {
    use Opcode::*;
    let mut body = vec![
        i(ADD, 1, 0, DATA as i64),
        i(ADD, 10, 0, 11),
        i(ADD, 11, 0, 22),
    ];
    // ENTER_UNCONSTRAINED, then, with t0 left 1 inside and 0 after the exit, the branch to
    // the code after the region.
    body.extend(syscall(3));
    body.push(b(BEQ, 5, 0, 24));
    body.push(i(ADD, 10, 0, 33));
    body.push(s(SD, 10, 1, 0));
    body.push(i(ADD, 12, 10, 1));
    // EXIT_UNCONSTRAINED: back to the branch.
    body.extend(syscall(4));
    body.push(r(ADD, 13, 10, 11));
    body.push(i(LD, 14, 1, 0));
    // HALT, exit code 0.
    body.push(i(ADD, 10, 0, 0));
    body.extend(syscall(0));
    Arc::new(Program::new(body, PC_BASE, PC_BASE))
}

/// A `COMMIT` and a `COMMIT_DEFERRED_PROOFS` of one word each, then `HALT`.
fn commits() -> Arc<Program> {
    use Opcode::*;
    let mut body = vec![i(ADD, 10, 0, 3), i(ADD, 11, 0, 0x1234)];
    body.extend(syscall(0x10));
    body.extend([i(ADD, 10, 0, 5), i(ADD, 11, 0, 0x7654)]);
    body.extend(syscall(0x1A));
    body.push(i(ADD, 10, 0, 0));
    body.extend(syscall(0));
    Arc::new(Program::new(body, PC_BASE, PC_BASE))
}

/// Every helper the code generator calls, each register-register and register-immediate form, and
/// the cases where the order of an instruction's accesses shows: a register read twice in one
/// instruction, a store whose value register is its base, a write to `x0`.
fn every_helper() -> Vec<Instruction> {
    use Opcode::*;
    vec![
        i(ADD, 1, 0, DATA as i64),
        i(ADD, 2, 0, -8),
        i(ADD, 3, 0, 0x7654_3210),
        r(ADD, 4, 3, 2),
        i(SUB, 5, 3, 17),
        r(SUB, 5, 5, 3),
        i(XOR, 6, 3, -1),
        r(XOR, 6, 6, 2),
        i(OR, 7, 2, 0x55),
        r(OR, 7, 7, 3),
        i(AND, 8, 3, 0xff0),
        r(AND, 8, 8, 2),
        i(SLL, 9, 3, 33),
        r(SLL, 9, 3, 3),
        i(SRL, 10, 2, 4),
        r(SRL, 10, 2, 3),
        i(SRA, 11, 2, 60),
        r(SRA, 11, 2, 3),
        i(SLT, 12, 2, -7),
        r(SLT, 12, 2, 3),
        i(SLTU, 13, 2, 9),
        r(SLTU, 13, 3, 2),
        r(ADDW, 14, 3, 3),
        r(SUBW, 14, 14, 2),
        r(SLLW, 15, 3, 3),
        r(SRLW, 15, 2, 3),
        r(SRAW, 15, 2, 3),
        r(MULW, 16, 3, 3),
        r(DIVW, 17, 2, 3),
        r(DIVUW, 17, 3, 0),
        r(REMW, 18, 3, 2),
        r(REMUW, 18, 2, 0),
        r(MUL, 19, 3, 2),
        r(MULH, 19, 2, 3),
        r(MULHU, 19, 2, 2),
        r(MULHSU, 19, 2, 3),
        r(DIV, 20, 2, 3),
        r(DIVU, 20, 3, 0),
        r(REM, 21, 2, 3),
        r(REMU, 21, 3, 0),
        r(ADD, 0, 3, 2),
        s(SD, 2, 1, 0),
        s(SW, 3, 1, 8),
        s(SH, 3, 1, 12),
        s(SB, 2, 1, 15),
        s(SD, 1, 1, 16),
        i(LD, 22, 1, 0),
        i(LW, 23, 1, 8),
        i(LWU, 24, 1, 8),
        i(LH, 25, 1, 12),
        i(LHU, 26, 1, 14),
        i(LB, 27, 1, 15),
        i(LBU, 28, 1, 15),
        i(LD, 1, 1, 16),
        i(LD, 0, 1, 0),
        Instruction::new(AUIPC, 29, 0x3000, 0, true, true),
    ]
}

/// The forms the code generator writes out inline rather than through a helper: an ALU instruction
/// on two immediates, the shape a constant is transpiled to, one writing `x0`, and the word forms
/// on two immediates and on a register and an immediate.
fn inline_forms() -> Vec<Instruction> {
    use Opcode::*;
    let folded =
        |opcode, rd, b: i64, c: i64| Instruction::new(opcode, rd, b as u64, c as u64, true, true);
    vec![
        folded(ADD, 1, 0x1234_5000, 0),
        folded(ADD, 2, -8, 3),
        folded(SUB, 3, 5, 9),
        folded(XOR, 4, -1, 0x55),
        folded(OR, 4, 0x0f, 0x30),
        folded(AND, 4, -2, 0xff),
        folded(SLL, 5, 1, 40),
        folded(SRL, 5, -16, 60),
        folded(SRA, 5, -64, 3),
        folded(SLT, 6, -1, 1),
        folded(SLTU, 6, -1, 1),
        folded(ADD, 0, 1, 2),
        folded(ADDW, 7, 0x7fff_ffff, 1),
        folded(SLLW, 7, 3, 31),
        folded(SRLW, 7, -16, 4),
        folded(SRAW, 7, -16, 4),
        i(ADDW, 8, 2, -3),
        i(SLLW, 9, 1, 5),
        i(SRLW, 10, 2, 7),
        i(SRAW, 11, 2, 7),
        i(ADDW, 2, 2, 1),
    ]
}

/// Misaligned loads and stores of every width (Zicclsm), inside a dword and across into
/// the next, over bytes aligned stores lay down first, and the stores' bytes read back. The first
/// misaligned access is the `LH` at `DATA + 1`.
fn misaligned() -> Vec<Instruction> {
    use Opcode::*;
    vec![
        i(ADD, 1, 0, DATA as i64),
        i(ADD, 2, 0, 0x7654_3210),
        i(ADD, 3, 0, -0x1234_5679),
        s(SW, 2, 1, 0),
        s(SW, 3, 1, 4),
        s(SW, 2, 1, 8),
        s(SW, 3, 1, 12),
        i(LH, 4, 1, 1),
        i(LHU, 5, 1, 7),
        i(LW, 6, 1, 2),
        i(LWU, 7, 1, 6),
        i(LD, 8, 1, 3),
        s(SH, 2, 1, 9),
        s(SH, 3, 1, 15),
        s(SW, 3, 1, 13),
        s(SW, 2, 1, 17),
        s(SD, 8, 1, 21),
        i(LD, 9, 1, 8),
        i(LD, 10, 1, 16),
        i(LD, 11, 1, 24),
        i(LW, 12, 1, 23),
        i(LD, 13, 1, 26),
    ]
}

/// The misaligned accesses in [`misaligned`].
const MISALIGNED_ACCESSES: u64 = 12;

/// The interpreter's record of the program's one chunk.
fn interpreted(program: Arc<Program>) -> EmulationRecord {
    let stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
    let opts = EmulatorOpts {
        chunk_size: 1 << 22,
        chunk_batch_size: 1,
        ..EmulatorOpts::test_opts()
    };
    let output = emulate_with_opts(program, &stdin, opts).expect("the interpreter runs it");
    assert_eq!(output.chunks, 1, "the program is one chunk");
    output
        .records
        .into_iter()
        .find(|record| record.is_cpu_chunk)
        .expect("a CPU chunk")
}

/// The AOT core's record of the program's one chunk, `run` driving it to its halt.
fn emitted(program: Arc<Program>, run: impl FnOnce(&mut AotEmulatorCore)) -> EmulationRecord {
    let mut emu = AotEmulatorCore::new(program, Vec::new());
    emu.emit_records();
    run(&mut emu);
    assert_eq!(emu.pc, 0, "the program ran to its halt");
    emu.finish_emitted_chunk();
    let mut chunks = emu.take_emitted_chunks();
    assert_eq!(chunks.len(), 1, "the program is one chunk");
    chunks.pop().unwrap().record
}

/// `instructions` CPU events and some local-memory windows on the interpreter's side first: a
/// comparison of two empty records would pass.
fn assert_same_events(interpreter: &EmulationRecord, aot: &EmulationRecord, instructions: usize) {
    assert_eq!(interpreter.cpu_steps().len(), instructions);
    assert!(!interpreter.cpu_local_memory_access.is_empty());
    for (index, (left, right)) in interpreter
        .cpu_steps()
        .iter()
        .zip(aot.cpu_steps().iter())
        .enumerate()
    {
        assert_eq!(left, right, "CPU event {index}, the interpreter's first");
    }
    let rows = |record: &EmulationRecord| -> Vec<_> {
        field_digests(record)
            .into_iter()
            .filter(|(field, ..)| WRITTEN.contains(field))
            .collect()
    };
    assert_eq!(
        rows(interpreter),
        rows(aot),
        "(field, len, digest), the interpreter's first"
    );
    assert_eq!(
        interpreter.cpu_local_memory_access.len(),
        aot.cpu_local_memory_access.len()
    );
    assert_eq!(
        boundary(interpreter),
        boundary(aot),
        "(start_pc, next_pc, exit_code), the interpreter's first"
    );
    assert_eq!(
        digests(interpreter),
        digests(aot),
        "(committed, deferred proofs) digest words, the interpreter's first"
    );
}

/// What a run leaves in the core for the next instruction, the snapshot and the chunk split: the
/// registers and their records, every memory cell touched and its record, the batch's prestate,
/// the clock and the split counters.
fn core_state(emu: &AotEmulatorCore) -> String {
    let cells = |memory: &ContiguousRiscvMemory| {
        let mut addrs: Vec<_> = memory.accessed_keys().collect();
        addrs.sort_unstable();
        addrs
            .into_iter()
            .map(|addr| (addr, memory.get(addr)))
            .collect::<Vec<_>>()
    };
    let split = &emu.chunk_split_state;
    format!(
        "{:?} {:?} {:?} {:?} {:?} {:#x} {} {} {} {:?} {:?}",
        emu.registers,
        emu.touched_registers,
        cells(&emu.memory),
        cells(&emu.memory_snapshot),
        (
            split.num_syscall_events,
            split.num_syscall_memory_events,
            split.num_memory_read_write_events,
            split.num_global_lookup_base,
            split.commit_in_flight,
            split.commits,
        ),
        emu.pc,
        emu.clk,
        emu.insn_count,
        emu.current_chunk,
        emu.committed_value_digest,
        emu.deferred_proofs_digest,
    )
}

/// The public values a `COMMIT` and a `COMMIT_DEFERRED_PROOFS` write, word by word.
fn digests(record: &EmulationRecord) -> ([u32; 8], [u32; 8]) {
    let public_values = &record.public_values;
    (
        public_values.committed_value_digest,
        public_values.deferred_proofs_digest,
    )
}

/// The public values the cut writes: where the chunk started and where it hands over.
fn boundary(record: &EmulationRecord) -> ([u32; 3], [u32; 3], u32) {
    let public_values = &record.public_values;
    (
        public_values.start_pc,
        public_values.next_pc,
        public_values.exit_code,
    )
}

// The paths the code generator writes out inline, copied from `instruction_translator.rs` statement
// for statement, with the chunk-boundary and yield checks left out: the chunk never fills here. An
// immediate is the instruction's, as the generated code hands it on. A `JALR` entry's error, which
// the generated code returns, is unwrapped: the programs here jump inside themselves.

/// `gen_jal`.
fn jal(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    let (rd, imm) = (inst.op_a as usize, inst.op_b);
    let emitting = emu.is_emitting();
    emu.jal_no_count(emitting, rd, pc, imm);
    emu.pc = pc.wrapping_add(imm);
    emu.update_insn_clock();
}

/// `gen_jalr`.
fn jalr(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    let (rd, rs1, imm) = (inst.op_a as usize, inst.op_b as usize, inst.op_c);
    let emitting = emu.is_emitting();
    let target = emu
        .jalr_no_count(emitting, rd, rs1, pc, imm)
        .expect("a jump inside the program");
    emu.pc = target;
    emu.update_insn_clock();
}

/// `gen_branch`.
fn branch(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    use Opcode::*;
    let (rs1, rs2, imm) = (inst.op_a as usize, inst.op_b as usize, inst.op_c);
    let emitting = emu.is_emitting();
    let taken = match inst.opcode {
        BEQ => emu.beq_no_count(emitting, rs1, rs2, pc, imm),
        BNE => emu.bne_no_count(emitting, rs1, rs2, pc, imm),
        BLT => emu.blt_no_count(emitting, rs1, rs2, pc, imm),
        BGE => emu.bge_no_count(emitting, rs1, rs2, pc, imm),
        BLTU => emu.bltu_no_count(emitting, rs1, rs2, pc, imm),
        BGEU => emu.bgeu_no_count(emitting, rs1, rs2, pc, imm),
        other => panic!("not a branch: {other:?}"),
    };
    emu.pc = if taken { pc.wrapping_add(imm) } else { pc + 4 };
    emu.update_insn_clock();
}

/// `gen_ecall`.
fn ecall(emu: &mut AotEmulatorCore, pc: u64) {
    let syscall_id = emu.read_reg_snapshot(5);
    let arg2 = emu.read_reg_c(11);
    let arg1 = emu.read_reg_b(10);
    let (return_value, new_next_pc, extra_cycles, _) = emu
        .execute_syscall(syscall_id, arg1, arg2)
        .expect("the syscall runs");
    emu.write_reg(5, return_value);
    emu.emit_ecall(pc, new_next_pc, return_value, arg1, arg2);
    emu.pc = new_next_pc;
    emu.update_insn_clock();
    if extra_cycles > 0 {
        emu.clk = emu.clk.wrapping_add(extra_cycles);
    }
}

/// `gen_alu_helper` on an instruction whose two operands are immediates, as a constant is.
fn folded_alu(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    use Opcode::*;
    let (rd, b, c) = (inst.op_a as usize, inst.op_b, inst.op_c);
    let a = match inst.opcode {
        ADD => b.wrapping_add(c),
        SUB => b.wrapping_sub(c),
        XOR => b ^ c,
        OR => b | c,
        AND => b & c,
        SLL => b.wrapping_shl((c & 0x3f) as u32),
        SRL => b.wrapping_shr((c & 0x3f) as u32),
        SRA => ((b as i64).wrapping_shr((c & 0x3f) as u32)) as u64,
        SLT => u64::from((b as i64) < (c as i64)),
        SLTU => u64::from(b < c),
        other => panic!("not folded inline: {other:?}"),
    };
    let emitting = emu.is_emitting();
    emu.constant_no_count(emitting, rd, a, b, c, pc + 4);
}

/// The word result of `opcode` on `lhs` and `rhs`, as `gen_word_alu_helper` folds it.
fn word(opcode: Opcode, lhs: u32, rhs: u32) -> u64 {
    let shamt = AotEmulatorCore::word_shift_amount_u32(u64::from(rhs));
    let value = match opcode {
        Opcode::ADDW => u64::from(lhs.wrapping_add(rhs)),
        Opcode::SLLW => u64::from(lhs.wrapping_shl(shamt)),
        Opcode::SRLW => u64::from(lhs.wrapping_shr(shamt)),
        Opcode::SRAW => (lhs as i32).wrapping_shr(shamt) as u32 as u64,
        other => panic!("not folded: {other:?}"),
    };
    AotEmulatorCore::sign_extend_word_result_u64(value)
}

/// `gen_word_alu_helper` on two immediates.
fn folded_word(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    let result = word(inst.opcode, inst.op_b as u32, inst.op_c as u32);
    let (b, c) = (inst.op_b, inst.op_c);
    let emitting = emu.is_emitting();
    emu.constant_no_count(emitting, inst.op_a as usize, result, b, c, pc + 4);
}

/// `gen_word_alu_helper` on a register and an immediate.
fn word_immediate(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    use Opcode::*;
    let (rd, rs1, imm, next) = (inst.op_a as usize, inst.op_b as usize, inst.op_c, pc + 4);
    let emitting = emu.is_emitting();
    match inst.opcode {
        ADDW => emu.adiw_no_count(emitting, rd, rs1, imm, next),
        SLLW => emu.sliw_no_count(emitting, rd, rs1, imm, next),
        SRLW => emu.sriw_no_count(emitting, rd, rs1, imm, next),
        SRAW => emu.saiw_no_count(emitting, rd, rs1, imm, next),
        other => panic!("no word immediate form: {other:?}"),
    }
}

/// Runs `program` through the `_no_count` helpers, one call per instruction as the code generator
/// writes them, and its `JALR`s and closing `HALT` as the generator inlines them.
fn run_helpers(emu: &mut AotEmulatorCore, program: &Program) {
    run_helpers_from(emu, &program.instructions, PC_BASE);
}

/// [`run_helpers`] for `instructions` placed from `pc_base`.
fn run_helpers_from(emu: &mut AotEmulatorCore, instructions: &[Instruction], pc_base: u64) {
    for (index, inst) in instructions.iter().enumerate() {
        let pc = pc_base + 4 * index as u64;
        match inst.opcode {
            Opcode::JALR => jalr(emu, pc, inst),
            Opcode::ECALL => ecall(emu, pc),
            _ => helper(emu, pc, inst),
        }
    }
}

/// Runs `program` to its halt as generated code runs it: the paths the generator writes out
/// inline as it writes them, every other instruction through its helper, and inside an
/// unconstrained block the fallback, to which a generated block hands every instruction there.
fn run_generated(emu: &mut AotEmulatorCore, program: &Program) {
    use Opcode::*;
    while emu.pc != 0 {
        if emu.is_unconstrained_mode() {
            emu.debug_interpret_single_step()
                .expect("the fallback runs it");
            continue;
        }
        let pc = emu.pc;
        let inst = &program.instructions[((pc - PC_BASE) / 4) as usize];
        let folded = inst.imm_b && inst.imm_c;
        match inst.opcode {
            JAL => jal(emu, pc, inst),
            JALR => jalr(emu, pc, inst),
            BEQ | BNE | BLT | BGE | BLTU | BGEU => branch(emu, pc, inst),
            ECALL => ecall(emu, pc),
            ADD | SUB | XOR | OR | AND | SLL | SRL | SRA | SLT | SLTU if folded => {
                folded_alu(emu, pc, inst)
            }
            ADDW | SLLW | SRLW | SRAW if folded => folded_word(emu, pc, inst),
            ADDW | SLLW | SRLW | SRAW if inst.imm_c => word_immediate(emu, pc, inst),
            _ => helper(emu, pc, inst),
        }
    }
}

/// The `_no_count` helper call the code generator writes for `inst` at `pc`.
fn helper(emu: &mut AotEmulatorCore, pc: u64, inst: &Instruction) {
    use Opcode::*;
    let next = pc + 4;
    let emitting = emu.is_emitting();
    let (rd, rs1, rs2, imm) = (
        inst.op_a as usize,
        inst.op_b as usize,
        inst.op_c as usize,
        inst.op_c,
    );
    match (inst.opcode, inst.imm_c) {
        (ADD, true) => emu.adi_no_count(emitting, rd, rs1, imm, next),
        (ADD, false) => emu.adr_no_count(emitting, rd, rs1, rs2, next),
        (SUB, true) => emu.sbi_no_count(emitting, rd, rs1, imm, next),
        (SUB, false) => emu.sbr_no_count(emitting, rd, rs1, rs2, next),
        (XOR, true) => emu.xri_no_count(emitting, rd, rs1, imm, next),
        (XOR, false) => emu.xrr_no_count(emitting, rd, rs1, rs2, next),
        (OR, true) => emu.ori_no_count(emitting, rd, rs1, imm, next),
        (OR, false) => emu.orr_no_count(emitting, rd, rs1, rs2, next),
        (AND, true) => emu.ani_no_count(emitting, rd, rs1, imm, next),
        (AND, false) => emu.anr_no_count(emitting, rd, rs1, rs2, next),
        (SLL, true) => emu.sli_no_count(emitting, rd, rs1, imm, next),
        (SLL, false) => emu.slr_no_count(emitting, rd, rs1, rs2, next),
        (SRL, true) => emu.sri_no_count(emitting, rd, rs1, imm, next),
        (SRL, false) => emu.srr_no_count(emitting, rd, rs1, rs2, next),
        (SRA, true) => emu.sai_no_count(emitting, rd, rs1, imm, next),
        (SRA, false) => emu.sar_no_count(emitting, rd, rs1, rs2, next),
        (SLT, true) => emu.slti_no_count(emitting, rd, rs1, imm, next),
        (SLT, false) => emu.sltr_no_count(emitting, rd, rs1, rs2, next),
        (SLTU, true) => emu.sltiu_no_count(emitting, rd, rs1, imm, next),
        (SLTU, false) => emu.sltru_no_count(emitting, rd, rs1, rs2, next),
        (ADDW, false) => emu.addw_no_count(emitting, rd, rs1, rs2, next),
        (SUBW, false) => emu.subw_no_count(emitting, rd, rs1, rs2, next),
        (SLLW, false) => emu.sllw_no_count(emitting, rd, rs1, rs2, next),
        (SRLW, false) => emu.srlw_no_count(emitting, rd, rs1, rs2, next),
        (SRAW, false) => emu.sraw_no_count(emitting, rd, rs1, rs2, next),
        (MULW, false) => emu.mulw_no_count(emitting, rd, rs1, rs2, next),
        (DIVW, false) => emu.divw_no_count(emitting, rd, rs1, rs2, next),
        (DIVUW, false) => emu.divuw_no_count(emitting, rd, rs1, rs2, next),
        (REMW, false) => emu.remw_no_count(emitting, rd, rs1, rs2, next),
        (REMUW, false) => emu.remuw_no_count(emitting, rd, rs1, rs2, next),
        (MUL, false) => emu.mul_no_count(emitting, rd, rs1, rs2, next),
        (MULH, false) => emu.mulh_no_count(emitting, rd, rs1, rs2, next),
        (MULHU, false) => emu.mulhu_no_count(emitting, rd, rs1, rs2, next),
        (MULHSU, false) => emu.mulhsu_no_count(emitting, rd, rs1, rs2, next),
        (DIV, false) => emu.div_no_count(emitting, rd, rs1, rs2, next),
        (DIVU, false) => emu.divu_no_count(emitting, rd, rs1, rs2, next),
        (REM, false) => emu.rem_no_count(emitting, rd, rs1, rs2, next),
        (REMU, false) => emu.remu_no_count(emitting, rd, rs1, rs2, next),
        (LD, true) => emu.ld_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (LW, true) => emu.lw_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (LWU, true) => emu.lwu_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (LH, true) => emu.lh_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (LHU, true) => emu.lhu_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (LB, true) => emu.lb_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (LBU, true) => emu.lbu_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (SD, true) => emu.sd_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (SW, true) => emu.sw_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (SH, true) => emu.sh_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (SB, true) => emu.sb_no_count(emitting, rd, rs1, imm, next).unwrap(),
        (AUIPC, _) => emu.apc_no_count(emitting, rd, pc, inst.op_b, next),
        other => panic!("no helper for {other:?}"),
    }
}

/// The program through the fallback interpreter alone, as the bootstrap stub's code runs it.
fn run_fallback(emu: &mut AotEmulatorCore) {
    AotProgram::STUB.run(emu).expect("the program runs");
}

#[test]
fn the_helpers_write_the_interpreters_records() {
    let program = program(every_helper());
    let interpreter = interpreted(program.clone());
    let aot = emitted(program.clone(), |emu| run_helpers(emu, &program));
    assert_same_events(&interpreter, &aot, program.instructions.len());
}

/// The digest words the commits program's comparisons rest on are there to compare.
#[test]
fn the_interpreter_writes_the_commits_digest_words() {
    let (committed, deferred) = digests(&interpreted(commits()));
    assert_eq!((committed[3], deferred[5]), (0x1234, 0x7654));
}

/// What only generated code runs: the jumps, branches and `ECALL`s it writes out inline, an
/// unconstrained region entered and left through them, and the folded and word forms.
#[test]
fn the_generated_code_writes_the_interpreters_records() {
    for program in [
        program(control_flow()),
        unconstrained(),
        program(inline_forms()),
        program(every_helper()),
        commits(),
    ] {
        let interpreter = interpreted(program.clone());
        let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
        emu.emit_records();
        run_generated(&mut emu, &program);
        emu.finish_emitted_chunk();
        let chunks = emu.take_emitted_chunks();
        let [chunk] = chunks.as_slice() else {
            panic!("{} chunks", chunks.len());
        };
        assert_same_events(&interpreter, &chunk.record, chunk.cycles as usize);
    }
}

/// A chunk boundary closes the record of the chunk before it, with that chunk's own counts and
/// pcs, and the halt closes the last: the two together hold every instruction once, and the second
/// starts where the first hands over.
#[test]
fn a_chunk_boundary_cuts_the_record_with_its_counts() {
    hold_records_unbounded();
    let program = program(every_helper());
    let instructions = program.instructions.len();
    let (first, rest) = program.instructions.split_at(20);

    let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
    emu.emit_records();
    run_helpers_from(&mut emu, first, PC_BASE);
    emu.chunk_split_config = ChunkSplitConfig::for_chunk_size(1, emu.max_syscall_cycles);
    assert!(emu.check_chunk_boundary(), "a one-cycle chunk is full");
    emu.chunk_split_config = ChunkSplitConfig::disabled(emu.max_syscall_cycles);
    run_helpers_from(&mut emu, rest, PC_BASE + 4 * 20);
    emu.finish_emitted_chunk();
    emu.finish_emitted_chunk();

    let chunks = emu.take_emitted_chunks();
    let shape: Vec<_> = chunks
        .iter()
        .map(|chunk| {
            (
                chunk.record.cpu_steps().len(),
                chunk.cycles,
                chunk.compiled_block_dispatches,
                chunk.fallback_insns,
            )
        })
        .collect();
    let later = (instructions - 20) as u64;
    assert_eq!(
        shape,
        [(20, 20, 0, 0), (instructions - 20, later, 0, 0)],
        "a second finish closes nothing"
    );
    assert!(
        chunks[1]
            .record
            .cpu_steps()
            .iter()
            .all(|event| event.chunk == 2),
        "the second chunk's events carry its number"
    );
    let pc = encode_public_value_pc_limbs;
    let handover = PC_BASE + 4 * 20;
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| boundary(&chunk.record))
            .collect::<Vec<_>>(),
        [(pc(PC_BASE), pc(handover), 0), (pc(handover), pc(0), 0)]
    );
    assert!(
        emu.take_emitted_chunks().is_empty(),
        "taken chunks are gone"
    );
}

/// The sink changes what is written and nothing else: every program, through the generated
/// code's paths and through the fallback, leaves the core as it does with the sink off.
#[test]
fn a_run_leaves_the_core_as_it_does_with_the_sink_off() {
    hold_records_unbounded();
    type Driver = fn(&mut AotEmulatorCore, &Program);
    for program in [
        program(every_helper()),
        program(control_flow()),
        unconstrained(),
        program(inline_forms()),
        commits(),
    ] {
        let drivers: [(&str, Driver); 2] = [
            ("generated", run_generated),
            ("fallback", |emu, _| run_fallback(emu)),
        ];
        for (driver, run) in drivers {
            let state = |emitting: bool| {
                let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
                if emitting {
                    emu.emit_records();
                }
                run(&mut emu, &program);
                assert_eq!(emu.pc, 0, "the program ran to its halt");
                core_state(&emu)
            };
            assert_eq!(
                state(true),
                state(false),
                "{driver}, the emitting run first"
            );
        }
    }
}

#[test]
fn the_fallback_writes_the_interpreters_records() {
    for program in [
        program(every_helper()),
        program(control_flow()),
        unconstrained(),
        program(inline_forms()),
        commits(),
    ] {
        let interpreter = interpreted(program.clone());
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        emu.emit_records();
        run_fallback(&mut emu);
        assert_eq!(emu.pc, 0, "the program ran to its halt");
        emu.finish_emitted_chunk();
        let chunks = emu.take_emitted_chunks();
        let [chunk] = chunks.as_slice() else {
            panic!("{} chunks", chunks.len());
        };
        assert_eq!(chunk.compiled_block_dispatches, 0);
        assert_eq!(
            chunk.fallback_insns, chunk.cycles,
            "the fallback ran it all"
        );
        assert_same_events(&interpreter, &chunk.record, chunk.cycles as usize);
    }
}

/// Misaligned loads and stores in a run whose records are proven: the AOT core writes the
/// interpreter's records for them, through the generated code's paths and through the fallback,
/// the next dword's access a local memory event and the history's unaligned step; it counts them;
/// and the sink changes nothing else.
#[test]
fn a_misaligned_access_writes_the_interpreters_records() {
    hold_records_unbounded();
    type Driver = fn(&mut AotEmulatorCore, &Program);
    let program = program(misaligned());
    let interpreter = interpreted(program.clone());
    let drivers: [(&str, Driver); 2] = [
        ("generated", run_generated),
        ("fallback", |emu, _| run_fallback(emu)),
    ];
    for (driver, run) in drivers {
        let core = |emitting: bool| {
            let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
            if emitting {
                emu.emit_records();
            }
            run(&mut emu, &program);
            assert_eq!(emu.pc, 0, "{driver}: the program ran to its halt");
            assert_eq!(emu.misaligned_accesses, MISALIGNED_ACCESSES, "{driver}");
            emu
        };
        let mut emu = core(true);
        assert_eq!(
            core_state(&emu),
            core_state(&core(false)),
            "{driver}, the emitting run first"
        );
        emu.finish_emitted_chunk();
        let chunks = emu.take_emitted_chunks();
        let [chunk] = chunks.as_slice() else {
            panic!("{driver}: {} chunks", chunks.len());
        };
        assert_same_events(&interpreter, &chunk.record, chunk.cycles as usize);
        let history = chunk
            .record
            .history
            .as_ref()
            .expect("a CPU chunk's history");
        assert_eq!(
            history.unaligned.len() as u64,
            MISALIGNED_ACCESSES,
            "{driver}: the history's unaligned steps"
        );
    }
}

/// In an unconstrained region nothing is proven, so a run whose records are proven executes a
/// misaligned access there, counts none, and rolls it back with the region: the AOT core as the
/// interpreter does.
#[test]
fn a_misaligned_access_in_an_unconstrained_region_is_rolled_back() {
    use Opcode::*;
    let mut body = vec![i(ADD, 1, 0, DATA as i64), i(ADD, 10, 0, 11)];
    body.extend(syscall(3));
    // The branch past the region once it has run, as in [`unconstrained`].
    body.push(b(BEQ, 5, 0, 24));
    body.push(i(ADD, 10, 0, -0x1234_5679));
    body.push(s(SD, 10, 1, 5));
    body.push(i(LW, 12, 1, 6));
    body.extend(syscall(4));
    body.push(i(LD, 14, 1, 8));
    body.push(i(ADD, 10, 0, 0));
    body.extend(syscall(0));
    let program = Arc::new(Program::new(body, PC_BASE, PC_BASE));

    let interpreter = interpreted(program.clone());
    let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
    emu.emit_records();
    run_generated(&mut emu, &program);
    assert_eq!(emu.misaligned_accesses, 0);
    assert_eq!(
        emu.registers[14].value, 0,
        "the region's store is rolled back"
    );
    emu.finish_emitted_chunk();
    let chunks = emu.take_emitted_chunks();
    let [chunk] = chunks.as_slice() else {
        panic!("{} chunks", chunks.len());
    };
    assert_same_events(&interpreter, &chunk.record, chunk.cycles as usize);
}

/// A chunk holds as many misaligned accesses as its `MemoryUnaligned` trace has rows, and closes
/// right after the one that fills it, mid-iteration here: the AOT core's fallback cuts each chunk
/// where the interpreter does. The loop's two loads an iteration, an instruction apart, are a `LW`
/// inside its dword and a `LD` across into the next; 1500 iterations make 3000.
#[test]
fn a_chunk_closes_at_its_misaligned_cap_where_the_interpreter_closes_it() {
    use Opcode::*;
    const CAP: usize = 1 << MLE_MEMORY_UNALIGNED_LOG_HEIGHT;
    const CHUNK_SIZE: u32 = 1 << 22;
    let program = program(vec![
        i(ADD, 1, 0, DATA as i64),
        i(ADD, 2, 0, 1500),
        i(LW, 3, 1, 2),
        r(ADD, 4, 3, 0),
        i(LD, 5, 1, 3),
        i(ADD, 2, 2, -1),
        b(BNE, 2, 0, -16),
    ]);
    let stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
    let opts = EmulatorOpts {
        chunk_size: CHUNK_SIZE,
        chunk_batch_size: 1,
        ..EmulatorOpts::test_opts()
    };
    let output = emulate_with_opts(program.clone(), &stdin, opts).expect("the interpreter runs it");
    let interpreter: Vec<(usize, usize)> = output
        .records
        .iter()
        .filter(|record| record.is_cpu_chunk)
        .map(|record| (record.cpu_steps().len(), unaligned_len(record)))
        .collect();
    // Two instructions before the loop and five an iteration: the 1024th access is the `LD` of
    // the 512th iteration, and the next chunk starts on the instruction after it.
    let full = 2 + 5 * 511 + 3;
    assert_eq!(
        interpreter,
        [
            (full, CAP),
            (full, CAP),
            // The last chunk ends with `program`'s three closing steps, `a0 = 0` and HALT.
            (2 + 7500 + 3 - 2 * full, 3000 - 2 * CAP)
        ]
    );

    let mut emu = AotEmulatorCore::new(program, Vec::new());
    emu.emit_records();
    emu.chunk_split_config = ChunkSplitConfig::for_chunk_size(CHUNK_SIZE, emu.max_syscall_cycles);
    run_fallback(&mut emu);
    assert_eq!(emu.pc, 0, "the program ran to its halt");
    emu.finish_emitted_chunk();
    let aot: Vec<(usize, usize)> = emu
        .take_emitted_chunks()
        .iter()
        .map(|chunk| (chunk.record.cpu_steps().len(), unaligned_len(&chunk.record)))
        .collect();
    assert_eq!(aot, interpreter);
}

/// A store below the segments ends the run with the same fault in the interpreter and in the AOT
/// core, through the generated code's helper and through the fallback.
#[test]
fn a_store_below_the_segments_ends_the_run_alike() {
    let program = program(vec![i(Opcode::ADD, 1, 0, 0x100), s(Opcode::SD, 1, 1, 0)]);
    let fault = TerminationReason::NullAccess {
        opcode: Opcode::SD,
        addr: 0x100,
    };
    let expected = EmulationError::from(AbnormalTermination::fault(fault)).to_string();
    let stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>().finalize();
    let opts = EmulatorOpts {
        chunk_size: 1 << 22,
        chunk_batch_size: 1,
        ..EmulatorOpts::test_opts()
    };
    let err = emulate_with_opts(program.clone(), &stdin, opts).expect_err("the interpreter");
    assert_eq!(err.to_string(), expected);

    let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
    run_helpers_from(&mut emu, &program.instructions[..1], PC_BASE);
    let err = emu
        .sd_no_count(false, 1, 1, 0, PC_BASE + 8)
        .expect_err("the helper");
    assert_eq!(err, expected, "generated");

    let mut emu = AotEmulatorCore::new(program, Vec::new());
    let err = AotProgram::STUB.run(&mut emu).expect_err("the fallback");
    assert!(err.contains(&expected), "fallback: {err}");
}
