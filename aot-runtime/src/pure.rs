//! Pure execution's host: guest memory, the system calls and the stepping interpreter.
//!
//! [`PureRun`] runs a guest to its halt and keeps only what `execute` reports: the bytes it
//! committed and its instruction count. It runs a pure-mode program's compiled blocks
//! ([`PureRun::run_compiled`]), or every instruction through its own stepping interpreter
//! ([`PureRun::run_interpreted`]). Either way the system calls, the pcs no block starts at and
//! every unconstrained region run here, with the interpreter's semantics: the precompiles and
//! hooks are the AOT core's code, reached through [`dispatch_precompile`] and the hook table.

use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    ffi::c_void,
    fmt,
    ops::Range,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::NonNull,
    sync::Arc,
};

use hashbrown::HashMap;
use pico_aot_pure::{
    sext32, Fault, PureProgram, PureState, ABI_VERSION, ACCESS_LB, ACCESS_LBU, ACCESS_LD,
    ACCESS_LH, ACCESS_LHU, ACCESS_LW, ACCESS_LWU, ACCESS_SB, ACCESS_SD, ACCESS_SH, ACCESS_SW,
    EXIT_CYCLE_LIMIT, EXIT_FAULT, EXIT_HALT, EXIT_HOST_ERROR, FAULT_BREAKPOINT, FAULT_ILLEGAL,
    FAULT_MISALIGNED_JUMP, FAULT_NULL_ACCESS, FAULT_OUTSIDE_PROGRAM, FAULT_OUT_OF_RANGE,
    FAULT_STACK_OVERFLOW, FAULT_STORE_TO_CODE, NEXT_HALT, NEXT_HOST_ERROR, SOURCE_FINGERPRINT,
};
use pico_vm::{
    compiler::riscv::{opcode::Opcode, program::Program, register::Register},
    emulator::riscv::{
        hook::{default_hook_map, Hook},
        riscv_emulator::{
            guard::{access_fault, access_width},
            AbnormalTermination, EmulationError, TerminationReason, MIN_MAIN_MEMORY_ADDR,
        },
        syscalls::SyscallCode,
    },
    primitives::{
        consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
        layout::{HEAP_END, MEMORY_SIZE, MIN_SEGMENT_ADDR, STACK_BOTTOM},
    },
};

use crate::{
    precompiles::PrecompileMemory,
    syscall::{
        decode_syscall_id_u32, decode_u32_abi_index, decode_u32_abi_word, digest_leaf_word_u32,
        dispatch_precompile, syscall_leaf_u32,
    },
};

/// Why a pure run failed: the emulation error the interpreter reports for it, where it has one,
/// and a message.
#[derive(Debug)]
pub struct PureFailure {
    pub error: Option<EmulationError>,
    pub message: String,
}

impl fmt::Display for PureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PureFailure {}

impl From<EmulationError> for PureFailure {
    fn from(error: EmulationError) -> Self {
        Self {
            message: error.to_string(),
            error: Some(error),
        }
    }
}

impl From<String> for PureFailure {
    fn from(message: String) -> Self {
        Self {
            error: None,
            message,
        }
    }
}

impl From<Fault> for PureFailure {
    /// The failure a fault in generated code stands for, as the interpreter reports the same
    /// fault.
    fn from(fault: Fault) -> Self {
        let Fault::Guest {
            kind,
            value,
            detail,
        } = fault
        else {
            return "pure host failed".to_string().into();
        };
        let reason = match kind {
            FAULT_BREAKPOINT => TerminationReason::Breakpoint { pc: value },
            FAULT_ILLEGAL => TerminationReason::IllegalInstruction { pc: value },
            FAULT_MISALIGNED_JUMP => TerminationReason::MisalignedJumpTarget {
                pc: detail,
                target: value,
            },
            FAULT_OUTSIDE_PROGRAM => TerminationReason::OutsideProgram { pc: value },
            FAULT_OUT_OF_RANGE | FAULT_NULL_ACCESS | FAULT_STACK_OVERFLOW | FAULT_STORE_TO_CODE => {
                let Some(opcode) = access_opcode(detail) else {
                    return format!("pure memory fault {kind} at {value:#x}, access {detail}")
                        .into();
                };
                let addr = value;
                match kind {
                    FAULT_OUT_OF_RANGE => TerminationReason::InvalidMemoryAccess { opcode, addr },
                    FAULT_NULL_ACCESS => TerminationReason::NullAccess { opcode, addr },
                    FAULT_STACK_OVERFLOW => TerminationReason::StackOverflow { opcode, addr },
                    _ => TerminationReason::StoreToCode { opcode, addr },
                }
            }
            other => return format!("unknown pure fault {other} ({value:#x})").into(),
        };
        EmulationError::from(AbnormalTermination::fault(reason)).into()
    }
}

/// The load or store an `ACCESS_*` names.
fn access_opcode(access: u64) -> Option<Opcode> {
    let Ok(access) = u32::try_from(access) else {
        return None;
    };
    Some(match access {
        ACCESS_LB => Opcode::LB,
        ACCESS_LH => Opcode::LH,
        ACCESS_LW => Opcode::LW,
        ACCESS_LBU => Opcode::LBU,
        ACCESS_LHU => Opcode::LHU,
        ACCESS_LWU => Opcode::LWU,
        ACCESS_LD => Opcode::LD,
        ACCESS_SB => Opcode::SB,
        ACCESS_SH => Opcode::SH,
        ACCESS_SW => Opcode::SW,
        ACCESS_SD => Opcode::SD,
        _ => return None,
    })
}

/// A panic's message, as a failure.
fn panic_failure(payload: Box<dyn std::any::Any + Send>) -> PureFailure {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "pure host panicked".to_string())
        .into()
}

const MEM_BYTES: usize = MEMORY_SIZE as usize;

/// Guest memory: one zeroed allocation over the address space, which the OS commits page by page
/// as the guest touches it. Word-aligned, so the allocator hands out fresh zero pages rather than
/// clearing them.
struct FlatMemory {
    ptr: *mut u8,
    /// The program's code, which a syscall may read but not write.
    code: Range<u64>,
    /// The first access a syscall made where no guest access may, which did not happen; the run
    /// ends when the syscall returns, as in the interpreter.
    fault: Option<TerminationReason>,
}

impl FlatMemory {
    fn layout() -> Layout {
        Layout::from_size_align(MEM_BYTES, 8).expect("guest memory layout")
    }

    fn new(code: Range<u64>) -> Self {
        // SAFETY: the layout's size is non-zero.
        let ptr = unsafe { alloc_zeroed(Self::layout()) };
        assert!(
            !ptr.is_null(),
            "cannot allocate {MEM_BYTES} bytes of guest memory"
        );
        Self {
            ptr,
            code,
            fault: None,
        }
    }

    /// Whether a syscall's `width`-byte access at `addr` may happen, as the AOT core's syscall
    /// accessors ask it; one that may not is kept as the run's fault, the first one only.
    fn allowed(&mut self, addr: u64, width: u64, store: bool) -> bool {
        match access_fault(Opcode::ECALL, addr, width, store, &self.code) {
            None => true,
            Some(reason) => {
                self.fault.get_or_insert(reason);
                false
            }
        }
    }

    /// The dword a syscall reads at `addr`, zero for one it may not read.
    fn syscall_dword(&mut self, addr: u64) -> u64 {
        if self.allowed(addr, 8, false) {
            self.dword(addr)
        } else {
            0
        }
    }

    fn syscall_set_dword(&mut self, addr: u64, value: u64) {
        if self.allowed(addr, 8, true) {
            self.set_dword(addr, value);
        }
    }

    /// The dword at `addr`.
    fn dword(&self, addr: u64) -> u64 {
        // SAFETY: `at` checked the span.
        unsafe { std::ptr::read_unaligned(self.at(addr, 8) as *const u64) }
    }

    fn set_dword(&mut self, addr: u64, value: u64) {
        // SAFETY: `at` checked the span.
        unsafe { std::ptr::write_unaligned(self.at(addr, 8) as *mut u64, value) }
    }

    /// A pointer to `width` bytes at `addr`. Panics outside the guest's memory, as the
    /// interpreter's memory does.
    fn at(&self, addr: u64, width: usize) -> *mut u8 {
        assert!(
            addr >= MIN_MAIN_MEMORY_ADDR,
            "memory access below floor 0x{MIN_MAIN_MEMORY_ADDR:08x}: 0x{addr:08x}"
        );
        assert!(
            (addr as usize)
                .checked_add(width)
                .is_some_and(|end| addr <= MEM_BYTES as u64 && end <= MEM_BYTES),
            "guest address out of range: {addr:#x}"
        );
        // SAFETY: in bounds, checked above.
        unsafe { self.ptr.add(addr as usize) }
    }
}

impl Drop for FlatMemory {
    fn drop(&mut self) {
        // SAFETY: allocated in `new` with the same layout.
        unsafe { dealloc(self.ptr, Self::layout()) }
    }
}

/// Precompiles run on plain memory: no clock, metadata or chunk accounting. Each access is checked
/// as the AOT core's syscall accessors check it: a span read as one access at its start, every
/// other dword on its own.
impl PrecompileMemory for FlatMemory {
    fn clk(&self) -> u32 {
        0
    }
    fn read_mem_dword_span_at_clk(&mut self, addr: u64, out: &mut [u64], _clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.syscall_dword(addr + (i as u64) * 8);
        }
    }
    fn write_mem_dword_span_at_clk(&mut self, addr: u64, values: &[u64], _clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            self.syscall_set_dword(addr + (i as u64) * 8, value);
        }
    }
    fn read_mem_dword_span_snapshot_syscall(&mut self, addr: u64, out: &mut [u64]) {
        if self.load_span_allowed(addr, out.len()) {
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = self.dword(addr + (i as u64) * 8);
            }
        } else {
            out.fill(0);
        }
    }
    fn load_span_allowed(&mut self, addr: u64, dwords: usize) -> bool {
        dwords == 0 || self.allowed(addr, 8 * dwords as u64, false)
    }
    fn read_mem_low32_slot_at_clk(&mut self, addr: u64, _clk: u32) -> u32 {
        self.syscall_dword(addr) as u32
    }
    fn write_mem_low32_slot_at_clk(&mut self, addr: u64, value: u32, _clk: u32) {
        self.syscall_set_dword(addr, u64::from(value));
    }
    fn read_mem_low32_slot_span_at_clk(&mut self, addr: u64, out: &mut [u32], _clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = self.syscall_dword(addr + (i as u64) * 8) as u32;
        }
    }
    fn write_mem_low32_slot_span_at_clk(&mut self, addr: u64, values: &[u32], _clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            self.syscall_set_dword(addr + (i as u64) * 8, u64::from(value));
        }
    }
    fn read_mem_dword_unsafe(&self, addr: u64) -> u64 {
        self.dword(addr)
    }
    fn account_syscall_memory_events(&mut self, _count: usize) {}
}

/// What an unconstrained region restores when it exits.
struct Unconstrained {
    /// The `ENTER_UNCONSTRAINED`'s pc.
    pc: u64,
    insn_count: u64,
    regs: [u64; 32],
    /// The misaligned-access count, which the region's accesses do not add to.
    misaligned: u64,
    committed_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    deferred_proofs_digest: [u32; DIGEST_SIZE],
    /// Each dword the region wrote, as it was before.
    journal: HashMap<u64, u64>,
}

/// Everything of a run but the registers, which [`PureState`] holds.
struct PureHost {
    program: Arc<Program>,
    mem: FlatMemory,
    input_stream: Vec<Vec<u8>>,
    input_stream_ptr: usize,
    public_values_stream: Vec<u8>,
    committed_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    deferred_proofs_digest: [u32; DIGEST_SIZE],
    stdout: String,
    stderr: String,
    hooks: HashMap<u32, Hook>,
    unconstrained: Option<Unconstrained>,
    /// Why a callback returned `NEXT_HOST_ERROR`.
    failure: Option<PureFailure>,
}

/// One guest run.
pub struct PureRun {
    state: PureState,
    /// Owned: from `Box::into_raw`, freed on drop. Held raw because `state.host` points at it too.
    host: NonNull<PureHost>,
}

impl Drop for PureRun {
    fn drop(&mut self) {
        // SAFETY: from `Box::into_raw` in `new`, and dropped once.
        drop(unsafe { Box::from_raw(self.host.as_ptr()) });
    }
}

impl PureRun {
    /// A run of `program` from its entry point, with `input_stream` as its input elements, that
    /// stops with [`EmulationError::ExceededCycleLimit`] past `max_cycles` instructions.
    pub fn new(program: Arc<Program>, input_stream: Vec<Vec<u8>>, max_cycles: u64) -> Self {
        let code = program.code();
        let mut mem = FlatMemory::new(code.clone());
        for (&addr, &value) in program.memory_image.iter() {
            mem.set_dword(addr, value);
        }
        let mem_ptr = mem.ptr;
        let host = NonNull::from(Box::leak(Box::new(PureHost {
            program,
            mem,
            input_stream,
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            committed_value_digest: [0; PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [0; DIGEST_SIZE],
            stdout: String::new(),
            stderr: String::new(),
            hooks: default_hook_map(),
            unconstrained: None,
            failure: None,
        })));
        let state = PureState {
            regs: [0; 32],
            insn_count: 0,
            max_insns: max_cycles,
            mem: mem_ptr,
            mem_len: MEM_BYTES as u64,
            mem_floor: MIN_SEGMENT_ADDR,
            guard_start: HEAP_END,
            guard_end: STACK_BOTTOM,
            code_start: code.start,
            code_end: code.end,
            misaligned: 0,
            host: host.as_ptr() as *mut c_void,
            ecall: host_ecall,
            step: host_step,
            fault: 0,
            fault_value: 0,
            fault_detail: 0,
        };
        Self { state, host }
    }

    fn host(&self) -> &PureHost {
        // SAFETY: owned by this run; the callbacks that also reach it run only inside `run_*`.
        unsafe { self.host.as_ref() }
    }

    /// Runs the guest through `program`'s compiled blocks, which must be the code generated from
    /// this run's ELF.
    pub fn run_compiled(&mut self, program: &PureProgram) -> Result<(), PureFailure> {
        if program.abi_version != ABI_VERSION || program.source_fingerprint != SOURCE_FINGERPRINT {
            return Err(format!(
                "pure program built against pico-aot-pure ABI {} ({:016x}); this host has ABI \
                 {ABI_VERSION} ({SOURCE_FINGERPRINT:016x})",
                program.abi_version, program.source_fingerprint
            )
            .into());
        }
        let pc = self.host().program.pc_start;
        // SAFETY: `state` points at this run's memory and host, which outlive the call; the
        // callbacks catch their panics, and the generated code does not panic.
        let exit = unsafe { (program.run)(&mut self.state, pc) };
        match exit {
            EXIT_HALT => Ok(()),
            EXIT_FAULT => Err(Fault::Guest {
                kind: self.state.fault,
                value: self.state.fault_value,
                detail: self.state.fault_detail,
            }
            .into()),
            EXIT_HOST_ERROR => Err(self.take_failure()),
            EXIT_CYCLE_LIMIT => {
                Err(EmulationError::ExceededCycleLimit(self.state.insn_count).into())
            }
            other => Err(format!("unknown pure exit code {other}").into()),
        }
    }

    /// Runs the guest through the stepping interpreter alone.
    pub fn run_interpreted(&mut self) -> Result<(), PureFailure> {
        // SAFETY: owned by this run, and reached by nothing else during the loop.
        let host = unsafe { self.host.as_mut() };
        let state = &mut self.state;
        let mut pc = host.program.pc_start;
        // The limit applies after each instruction, before the run ends, as in the interpreter.
        catch_unwind(AssertUnwindSafe(|| loop {
            pc = host.step(state, pc)?;
            if state.insn_count >= state.max_insns {
                return Err(EmulationError::ExceededCycleLimit(state.insn_count).into());
            }
            if pc == NEXT_HALT {
                return Ok(());
            }
        }))
        .unwrap_or_else(|payload| Err(panic_failure(payload)))
    }

    /// The bytes the guest committed, in commit order.
    pub fn committed_bytes(&self) -> &[u8] {
        &self.host().public_values_stream
    }

    /// Instructions run: what the interpreter counts as the run's cycles.
    pub fn cycles(&self) -> u64 {
        self.state.insn_count
    }

    /// Loads and stores whose address is not a multiple of their width, outside unconstrained
    /// regions, as the interpreter counts them.
    pub fn misaligned_accesses(&self) -> u64 {
        self.state.misaligned
    }

    /// The registers as the run left them.
    pub fn registers(&self) -> [u64; 32] {
        self.state.regs
    }

    fn take_failure(&mut self) -> PureFailure {
        // SAFETY: owned by this run, and no callback runs now.
        unsafe { self.host.as_mut() }
            .failure
            .take()
            .unwrap_or_else(|| "pure host failed without a reason".to_string().into())
    }
}

/// [`PureState::ecall`]: the host's [`PureHost::ecall`].
unsafe extern "C" fn host_ecall(state: *mut PureState, pc: u64) -> u64 {
    host_call(state, |host, state| host.ecall(state, pc))
}

/// [`PureState::step`]: the host's [`PureHost::step`].
unsafe extern "C" fn host_step(state: *mut PureState, pc: u64) -> u64 {
    host_call(state, |host, state| host.step(state, pc))
}

/// Calls into the host from generated code, and keeps a failure for [`PureRun`] to report. A
/// panic stops here: it may not unwind through the `extern "C"` frames between.
fn host_call(
    state: *mut PureState,
    call: impl FnOnce(&mut PureHost, &mut PureState) -> Result<u64, PureFailure>,
) -> u64 {
    // SAFETY: the generated code passes back the state `PureRun` handed it, whose `host` is that
    // run's host; the two are separate allocations.
    let (state, host) = unsafe {
        let state = &mut *state;
        let host = &mut *(state.host as *mut PureHost);
        (state, host)
    };
    let failure = match catch_unwind(AssertUnwindSafe(|| call(host, state))) {
        Ok(Ok(next)) => return next,
        Ok(Err(failure)) => failure,
        Err(payload) => panic_failure(payload),
    };
    host.failure = Some(failure);
    NEXT_HOST_ERROR
}

impl PureHost {
    /// Runs the one instruction at `pc` with the generated code's semantics. Returns the next pc,
    /// or [`NEXT_HALT`] after `HALT`.
    fn step(&mut self, state: &mut PureState, pc: u64) -> Result<u64, PureFailure> {
        // As the interpreter: only `HALT` ends a run, and a pc outside the program is refused.
        let Some(inst) = self.program.try_fetch(pc) else {
            return Err(EmulationError::outside_program(pc).into());
        };
        state.insn_count += 1;
        let (a, b_raw, c_raw) = (usize::from(inst.op_a), inst.op_b, inst.op_c);
        let next = pc.wrapping_add(4);
        // ALU operands. Other opcodes read their fields themselves, so a field that is no
        // register index reads as 0 here.
        let operand = |raw: u64, imm: bool| match imm {
            true => raw,
            false => state.regs.get(raw as usize).copied().unwrap_or(0),
        };
        let (b, c) = (operand(b_raw, inst.imm_b), operand(c_raw, inst.imm_c));
        let alu: fn(u64, u64) -> u64 = match inst.opcode {
            Opcode::ADD => pico_aot_pure::add,
            Opcode::SUB => pico_aot_pure::sub,
            Opcode::XOR => pico_aot_pure::xor,
            Opcode::OR => pico_aot_pure::or,
            Opcode::AND => pico_aot_pure::and,
            Opcode::SLL => pico_aot_pure::sll,
            Opcode::SRL => pico_aot_pure::srl,
            Opcode::SRA => pico_aot_pure::sra,
            Opcode::SLT => pico_aot_pure::slt,
            Opcode::SLTU => pico_aot_pure::sltu,
            Opcode::ADDW => pico_aot_pure::addw,
            Opcode::SUBW => pico_aot_pure::subw,
            Opcode::SLLW => pico_aot_pure::sllw,
            Opcode::SRLW => pico_aot_pure::srlw,
            Opcode::SRAW => pico_aot_pure::sraw,
            Opcode::MUL => pico_aot_pure::mul,
            Opcode::MULH => pico_aot_pure::mulh,
            Opcode::MULHU => pico_aot_pure::mulhu,
            Opcode::MULHSU => pico_aot_pure::mulhsu,
            Opcode::DIV => pico_aot_pure::div,
            Opcode::DIVU => pico_aot_pure::divu,
            Opcode::REM => pico_aot_pure::rem,
            Opcode::REMU => pico_aot_pure::remu,
            Opcode::MULW => pico_aot_pure::mulw,
            Opcode::DIVW => pico_aot_pure::divw,
            Opcode::DIVUW => pico_aot_pure::divuw,
            Opcode::REMW => pico_aot_pure::remw,
            Opcode::REMUW => pico_aot_pure::remuw,
            Opcode::AUIPC => {
                state.w(a, pc.wrapping_add(b_raw));
                return Ok(next);
            }
            Opcode::LB => {
                return state
                    .lb(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::LH => {
                return state
                    .lh(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::LW => {
                return state
                    .lw(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::LBU => {
                return state
                    .lbu(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::LHU => {
                return state
                    .lhu(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::LWU => {
                return state
                    .lwu(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::LD => {
                return state
                    .ld(a, b_raw as usize, c_raw)
                    .map(|_| next)
                    .map_err(Into::into)
            }
            Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
                // S-type: op_a is the value register, op_b the base, op_c the offset.
                let (rs2, rs1) = (a, b_raw as usize);
                let addr = state.regs[rs1].wrapping_add(sext32(c_raw));
                self.journal_store(addr, access_width(inst.opcode));
                let stored = match inst.opcode {
                    Opcode::SB => state.sb(rs2, rs1, c_raw),
                    Opcode::SH => state.sh(rs2, rs1, c_raw),
                    Opcode::SW => state.sw(rs2, rs1, c_raw),
                    _ => state.sd(rs2, rs1, c_raw),
                };
                return stored.map(|_| next).map_err(Into::into);
            }
            Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
                let (x, y) = (state.regs[a], state.regs[b_raw as usize]);
                let taken = match inst.opcode {
                    Opcode::BEQ => x == y,
                    Opcode::BNE => x != y,
                    Opcode::BLT => (x as i64) < (y as i64),
                    Opcode::BGE => (x as i64) >= (y as i64),
                    Opcode::BLTU => x < y,
                    _ => x >= y,
                };
                if !taken {
                    return Ok(next);
                }
                let target = pc.wrapping_add(sext32(c_raw));
                state.check_jump(pc, target)?;
                return Ok(target);
            }
            Opcode::JAL => {
                let target = pc.wrapping_add(sext32(b_raw));
                state.check_jump(pc, target)?;
                state.link(a, pc);
                return Ok(target);
            }
            Opcode::JALR => return Ok(state.jalr(a, b_raw as usize, pc, c_raw)?),
            Opcode::ECALL => return self.ecall(state, pc),
            Opcode::EBREAK => {
                return Err(Fault::Guest {
                    kind: FAULT_BREAKPOINT,
                    value: pc,
                    detail: 0,
                }
                .into())
            }
            Opcode::UNIMP => {
                return Err(Fault::Guest {
                    kind: FAULT_ILLEGAL,
                    value: pc,
                    detail: 0,
                }
                .into())
            }
        };
        state.w(a, alu(b, c));
        Ok(next)
    }

    /// In an unconstrained region, keeps the dwords a `width`-byte store to `addr` changes, the
    /// first time; a misaligned one can change two. A store outside memory faults instead, so it
    /// keeps nothing.
    fn journal_store(&mut self, addr: u64, width: u64) {
        let Some(region) = self.unconstrained.as_mut() else {
            return;
        };
        let first = addr & !7;
        let last = addr.wrapping_add(width - 1) & !7;
        for dword in [first, last] {
            if (MIN_MAIN_MEMORY_ADDR..=(MEM_BYTES - 8) as u64).contains(&dword) {
                let mem = &self.mem;
                region
                    .journal
                    .entry(dword)
                    .or_insert_with(|| mem.dword(dword));
            }
        }
    }

    /// Runs the `ECALL` at `pc`. Returns the next pc or [`NEXT_HALT`].
    fn ecall(&mut self, state: &mut PureState, pc: u64) -> Result<u64, PureFailure> {
        let id = decode_syscall_id_u32(state.regs[Register::X5 as usize])?;
        let code = SyscallCode::try_from_u32(id).ok_or(EmulationError::UnsupportedSyscall(id))?;
        let arg1 = state.regs[Register::X10 as usize];
        let arg2 = state.regs[Register::X11 as usize];
        if self.unconstrained.is_some()
            && !matches!(code, SyscallCode::WRITE | SyscallCode::EXIT_UNCONSTRAINED)
        {
            return Err(EmulationError::InvalidSyscallUsage(u64::from(code.syscall_id())).into());
        }
        let ret = u64::from(id);
        let next = pc.wrapping_add(4);
        // Every code is named: a syscall added to the VM does not build here until it runs here.
        let (ret, next) = match code {
            SyscallCode::WRITE => {
                self.write(state, arg1, arg2)?;
                (ret, next)
            }
            SyscallCode::HINT_LEN => (self.hint_len()?, next),
            SyscallCode::HINT_READ => {
                self.hint_read(arg1, arg2)?;
                (ret, next)
            }
            SyscallCode::COMMIT => {
                let idx = decode_u32_abi_index(arg1, PV_DIGEST_NUM_WORDS, "commit word_idx")?;
                self.committed_value_digest[idx] =
                    digest_leaf_word_u32(arg2, "commit digest word")?;
                (ret, next)
            }
            SyscallCode::COMMIT_DEFERRED_PROOFS => {
                let idx = decode_u32_abi_index(arg1, DIGEST_SIZE, "deferred word_idx")?;
                self.deferred_proofs_digest[idx] =
                    digest_leaf_word_u32(arg2, "deferred digest word")?;
                (ret, next)
            }
            SyscallCode::VERIFY_PICO_PROOF => (ret, next),
            SyscallCode::ENTER_UNCONSTRAINED => return self.unconstrained_region(state, pc),
            SyscallCode::EXIT_UNCONSTRAINED => match self.unconstrained.take() {
                Some(region) => {
                    state.regs = region.regs;
                    state.insn_count = region.insn_count;
                    state.misaligned = region.misaligned;
                    self.committed_value_digest = region.committed_value_digest;
                    self.deferred_proofs_digest = region.deferred_proofs_digest;
                    for (addr, value) in region.journal {
                        self.mem.set_dword(addr, value);
                    }
                    (0, region.pc.wrapping_add(4))
                }
                None => (0, next),
            },
            SyscallCode::HALT => {
                let exit_code = decode_u32_abi_word(arg1, "halt exit_code")?;
                if exit_code != 0 {
                    return Err(
                        EmulationError::from(AbnormalTermination::halt(exit_code, arg2)).into(),
                    );
                }
                state.w(Register::X5 as usize, ret);
                return Ok(NEXT_HALT);
            }
            SyscallCode::SHA_EXTEND
            | SyscallCode::SHA_COMPRESS
            | SyscallCode::ED_ADD
            | SyscallCode::ED_DECOMPRESS
            | SyscallCode::KECCAK_PERMUTE
            | SyscallCode::SECP256K1_ADD
            | SyscallCode::SECP256K1_DOUBLE
            | SyscallCode::SECP256K1_DECOMPRESS
            | SyscallCode::BN254_ADD
            | SyscallCode::BN254_DOUBLE
            | SyscallCode::BLS12381_DECOMPRESS
            | SyscallCode::UINT256_MUL
            | SyscallCode::BLS12381_ADD
            | SyscallCode::BLS12381_DOUBLE
            | SyscallCode::BLS12381_FP_ADD
            | SyscallCode::BLS12381_FP_SUB
            | SyscallCode::BLS12381_FP_MUL
            | SyscallCode::BLS12381_FP2_ADD
            | SyscallCode::BLS12381_FP2_SUB
            | SyscallCode::BLS12381_FP2_MUL
            | SyscallCode::BN254_FP_ADD
            | SyscallCode::BN254_FP_SUB
            | SyscallCode::BN254_FP_MUL
            | SyscallCode::BN254_FP2_ADD
            | SyscallCode::BN254_FP2_SUB
            | SyscallCode::BN254_FP2_MUL
            | SyscallCode::SECP256K1_FP_ADD
            | SyscallCode::SECP256K1_FP_SUB
            | SyscallCode::SECP256K1_FP_MUL
            | SyscallCode::POSEIDON2_PERMUTE
            | SyscallCode::SECP256R1_ADD
            | SyscallCode::SECP256R1_DOUBLE
            | SyscallCode::SECP256R1_DECOMPRESS
            | SyscallCode::BLS12381_G2_ADD
            | SyscallCode::BLS12381_G2_DOUBLE => {
                if !dispatch_precompile(&mut self.mem, id, arg1, arg2)? {
                    return Err(EmulationError::UnsupportedSyscall(id).into());
                }
                if let Some(reason) = self.mem.fault.take() {
                    return Err(EmulationError::from(AbnormalTermination::fault(reason)).into());
                }
                (ret, next)
            }
        };
        state.w(Register::X5 as usize, ret);
        Ok(next)
    }

    /// `ENTER_UNCONSTRAINED` at `pc`: steps the region to its `EXIT_UNCONSTRAINED`, which rolls the
    /// registers, memory, digests and instruction count back; input the region added stays.
    /// Returns where the guest resumes.
    fn unconstrained_region(&mut self, state: &mut PureState, pc: u64) -> Result<u64, PureFailure> {
        self.unconstrained = Some(Unconstrained {
            pc,
            insn_count: state.insn_count,
            regs: state.regs,
            misaligned: state.misaligned,
            committed_value_digest: self.committed_value_digest,
            deferred_proofs_digest: self.deferred_proofs_digest,
            journal: HashMap::new(),
        });
        state.w(Register::X5 as usize, 1);
        // The region's instructions count toward the limit until it rolls the count back.
        let mut pc = pc.wrapping_add(4);
        while self.unconstrained.is_some() {
            pc = self.step(state, pc)?;
            if state.insn_count >= state.max_insns {
                return Err(EmulationError::ExceededCycleLimit(state.insn_count).into());
            }
            if pc == NEXT_HALT {
                return Err(EmulationError::UnconstrainedEnd.into());
            }
        }
        Ok(pc)
    }

    fn write(&mut self, state: &PureState, fd: u64, buf: u64) -> Result<(), PureFailure> {
        let fd = syscall_leaf_u32(fd, "write fd")?;
        let nbytes = state.regs[Register::X12 as usize] as usize;
        // An empty write reads nothing, so its pointer may dangle, as an empty Rust slice's does.
        if nbytes > 0 && !self.mem.allowed(buf, nbytes as u64, false) {
            return Err(self.syscall_fault());
        }
        let bytes = match nbytes {
            0 => Vec::new(),
            // SAFETY: `at` checked the span against memory.
            _ => unsafe { std::slice::from_raw_parts(self.mem.at(buf, nbytes), nbytes) }.to_vec(),
        };
        match fd {
            1 | 2 => {
                let text = String::from_utf8(bytes)
                    .map_err(|_| "write syscall emitted invalid UTF-8".to_string())?;
                self.output(fd, &text);
            }
            3 => self.public_values_stream.extend_from_slice(&bytes),
            // Read next, ahead of input the guest has not read yet, as in the interpreter.
            4 => self.input_stream.insert(self.input_stream_ptr, bytes),
            fd => match self.hooks.get(&fd).copied() {
                Some(hook) => {
                    let answer = hook(&bytes);
                    let at = self.input_stream_ptr;
                    self.input_stream.splice(at..at, answer);
                }
                // As the interpreter and the AOT core: warn and carry on.
                None => log::warn!("tried to write to unknown file descriptor {fd}"),
            },
        }
        Ok(())
    }

    /// The fault [`FlatMemory::allowed`] just kept, as the run's failure.
    fn syscall_fault(&mut self) -> PureFailure {
        match self.mem.fault.take() {
            Some(reason) => EmulationError::from(AbnormalTermination::fault(reason)).into(),
            None => "syscall access refused without a fault".to_string().into(),
        }
    }

    /// Logs the guest's stdout or stderr a line at a time, as the AOT core does.
    fn output(&mut self, fd: u32, text: &str) {
        let (prefix, buffer) = match fd {
            1 => ("stdout", &mut self.stdout),
            _ => ("stderr", &mut self.stderr),
        };
        buffer.push_str(text);
        while let Some(end) = buffer.find('\n') {
            log::info!("{prefix}> {}", &buffer[..end]);
            buffer.drain(..=end);
        }
    }

    fn hint_len(&self) -> Result<u64, PureFailure> {
        match self.input_stream.get(self.input_stream_ptr) {
            Some(element) => Ok(element.len() as u64),
            None => Err(EmulationError::InsufficientInput {
                stream_ptr: self.input_stream_ptr,
                stream_len: self.input_stream.len(),
            }
            .into()),
        }
    }

    fn hint_read(&mut self, ptr: u64, len: u64) -> Result<(), PureFailure> {
        let stream_ptr = self.input_stream_ptr;
        let Some(element) = self.input_stream.get(stream_ptr) else {
            return Err(EmulationError::InsufficientInput {
                stream_ptr,
                stream_len: self.input_stream.len(),
            }
            .into());
        };
        let supplied = element.len();
        if usize::try_from(len).ok() != Some(supplied) {
            return Err(EmulationError::InvalidHintRead(format!(
                "length mismatch: the guest asked for {len} byte(s), input element {stream_ptr} \
                 holds {supplied}"
            ))
            .into());
        }
        if !ptr.is_multiple_of(8) {
            return Err(EmulationError::InvalidHintRead(format!(
                "address 0x{ptr:016x} is not aligned to 8 bytes"
            ))
            .into());
        }
        // The dwords the hint lands in are written like a store's; an empty hint writes nothing.
        if supplied > 0 && !self.mem.allowed(ptr, 8 * supplied.div_ceil(8) as u64, true) {
            return Err(self.syscall_fault());
        }
        // Whole dwords, the last zero-padded, as the AOT core writes them. It also refuses a
        // dword something already wrote; plain memory can only tell one that holds a value.
        let element = std::mem::take(&mut self.input_stream[stream_ptr]);
        for (i, chunk) in element.chunks(8).enumerate() {
            let addr = ptr + (i as u64) * 8;
            let mut word = [0u8; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            let old = self.mem.dword(addr);
            if old != 0 {
                return Err(EmulationError::InvalidHintRead(format!(
                    "address is initialized already: addr=0x{addr:016x} ptr=0x{ptr:016x} \
                     old_dword=0x{old:016x}"
                ))
                .into());
            }
            self.mem.set_dword(addr, u64::from_le_bytes(word));
        }
        self.input_stream[stream_ptr] = element;
        self.input_stream_ptr += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pico_vm::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::riscv::syscalls::SyscallCode,
    };

    use pico_vm::emulator::riscv::riscv_emulator::{EmulationError, TerminationReason};

    use super::PureRun;
    use crate::{AotEmulatorCore, AotProgram};

    fn addi(rd: u8, imm: u64) -> Instruction {
        Instruction::new(Opcode::ADD, rd, 0, imm, false, true)
    }

    fn ecall() -> Instruction {
        Instruction::new(Opcode::ECALL, 5, 10, 11, false, false)
    }

    /// An unconstrained region that sets `x6` and stores it at 0x2_0000, then a load of 0x2_0000
    /// into `x8` after the region, and a halt.
    fn unconstrained_program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                addi(5, SyscallCode::ENTER_UNCONSTRAINED as u64), // 0x1000
                ecall(),                                          // 0x1004
                Instruction::new(Opcode::BEQ, 5, 0, 0x1c, false, true), // 0x1008: to 0x1024
                addi(7, 0x2_0000),                                // 0x100c
                addi(6, 0x55),                                    // 0x1010
                Instruction::new(Opcode::SD, 6, 7, 0, false, true), // 0x1014
                addi(5, SyscallCode::EXIT_UNCONSTRAINED as u64),  // 0x1018
                ecall(),                                          // 0x101c
                Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true), // 0x1020
                addi(7, 0x2_0000),                                // 0x1024
                Instruction::new(Opcode::LD, 8, 7, 0, false, true), // 0x1028
                addi(5, SyscallCode::HALT as u64),                // 0x102c
                addi(10, 0),                                      // 0x1030
                ecall(),                                          // 0x1034
            ],
            0x1000,
            0x1000,
        ))
    }

    #[test]
    fn an_unconstrained_region_rolls_back_as_in_the_aot_core() {
        let mut core = AotEmulatorCore::new(unconstrained_program(), Vec::new());
        AotProgram::STUB
            .run(&mut core)
            .expect("the AOT core runs it");

        let mut run = PureRun::new(unconstrained_program(), Vec::new(), u64::MAX);
        run.run_interpreted().expect("pure execution runs it");

        let core_registers: [u64; 32] = std::array::from_fn(|i| core.registers[i].value);
        assert_eq!(run.registers(), core_registers, "the registers differ");
        assert_eq!(
            run.cycles(),
            core.insn_count,
            "the instruction counts differ"
        );
        assert_eq!(
            run.registers()[6],
            0,
            "the region's register write rolled back"
        );
        assert_eq!(run.registers()[8], 0, "the region's store rolled back");
    }

    /// `JAL x0, 0`: jumps to itself.
    fn spin() -> Instruction {
        Instruction::new(Opcode::JAL, 0, 0, 0, true, true)
    }

    fn run(instructions: Vec<Instruction>, max_cycles: u64) -> Result<(), super::PureFailure> {
        let program = Arc::new(Program::new(instructions, 0x1000, 0x1000));
        PureRun::new(program, Vec::new(), max_cycles).run_interpreted()
    }

    fn failure_is(result: Result<(), super::PureFailure>, wanted: fn(&EmulationError) -> bool) {
        let failure = result.expect_err("the run fails");
        assert!(failure.error.as_ref().is_some_and(wanted), "{failure}");
    }

    #[test]
    fn a_spinning_guest_stops_at_the_cycle_limit() {
        failure_is(run(vec![spin()], 100), |e| {
            matches!(e, EmulationError::ExceededCycleLimit(100))
        });
    }

    #[test]
    fn a_spinning_unconstrained_region_stops_at_the_cycle_limit() {
        // The region spins at 0x1008.
        let program = vec![
            addi(5, SyscallCode::ENTER_UNCONSTRAINED as u64),
            ecall(),
            spin(),
        ];
        failure_is(run(program, 100), |e| {
            matches!(e, EmulationError::ExceededCycleLimit(_))
        });
    }

    /// The termination reason of a run that ends abnormally.
    fn reason(result: Result<(), super::PureFailure>) -> TerminationReason {
        let failure = result.expect_err("the run fails");
        match failure.error {
            Some(EmulationError::AbnormalTermination(t)) => t.reason,
            _ => panic!("not an abnormal termination: {failure}"),
        }
    }

    #[test]
    fn a_jump_outside_the_program_is_refused() {
        // x1 = 1 << 32, then JALR to it.
        let program = vec![
            addi(1, 1),
            Instruction::new(Opcode::SLL, 1, 1, 32, false, true),
            Instruction::new(Opcode::JALR, 0, 1, 0, false, true),
        ];
        assert_eq!(
            reason(run(program, u64::MAX)),
            TerminationReason::OutsideProgram { pc: 1 << 32 }
        );
    }

    #[test]
    fn a_misaligned_jump_is_refused_before_the_link() {
        // JAL x1, +2 at 0x1000.
        let program = vec![Instruction::new(Opcode::JAL, 1, 2, 0, true, true)];
        assert_eq!(
            reason(run(program, u64::MAX)),
            TerminationReason::MisalignedJumpTarget {
                pc: 0x1000,
                target: 0x1002
            }
        );
    }

    #[test]
    fn running_off_the_end_is_refused() {
        assert_eq!(
            reason(run(vec![addi(1, 1)], u64::MAX)),
            TerminationReason::OutsideProgram { pc: 0x1004 }
        );
    }

    /// A hint written to fd 4 is read before the input the guest has not read yet.
    #[test]
    fn a_hint_is_read_ahead_of_unread_input() {
        // WRITE fd 4, 3 bytes at 0x2_0000; then HINT_LEN into x5 and halt.
        let program = Arc::new(Program::new(
            vec![
                addi(5, SyscallCode::WRITE as u64),
                addi(10, 4),
                addi(11, 0x2_0000),
                addi(12, 3),
                ecall(),
                addi(5, SyscallCode::HINT_LEN as u64),
                ecall(),
                addi(6, 0),
                Instruction::new(Opcode::ADD, 6, 5, 0, false, true),
                addi(5, SyscallCode::HALT as u64),
                addi(10, 0),
                ecall(),
            ],
            0x1000,
            0x1000,
        ));
        let mut run = PureRun::new(program, vec![vec![0; 7]], u64::MAX);
        run.run_interpreted().expect("pure execution runs it");
        assert_eq!(
            run.registers()[6],
            3,
            "HINT_LEN saw the hint, not the input"
        );
    }

    #[test]
    fn accesses_follow_the_memory_guard() {
        use pico_vm::primitives::layout::{HEAP_END, MEMORY_SIZE};
        let load = |addr: u64| {
            run(
                vec![
                    addi(1, addr),
                    Instruction::new(Opcode::LD, 2, 1, 0, false, true),
                ],
                u64::MAX,
            )
        };
        let ld = Opcode::LD;
        assert_eq!(
            reason(load(0x100)),
            TerminationReason::NullAccess {
                opcode: ld,
                addr: 0x100
            }
        );
        assert_eq!(
            reason(load(HEAP_END - 4)),
            TerminationReason::StackOverflow {
                opcode: ld,
                addr: HEAP_END - 4
            }
        );
        assert_eq!(
            reason(load(MEMORY_SIZE - 4)),
            TerminationReason::InvalidMemoryAccess {
                opcode: ld,
                addr: MEMORY_SIZE - 4
            }
        );
        // SW into its own code, which lies above the null region here.
        let program = Arc::new(Program::new(
            vec![
                addi(1, 0x2_0000),
                Instruction::new(Opcode::SW, 0, 1, 0, false, true),
            ],
            0x2_0000,
            0x2_0000,
        ));
        assert_eq!(
            reason(PureRun::new(program, Vec::new(), u64::MAX).run_interpreted()),
            TerminationReason::StoreToCode {
                opcode: Opcode::SW,
                addr: 0x2_0000
            }
        );
    }

    #[test]
    fn misaligned_accesses_run_and_are_counted() {
        // A misaligned SD across two dwords and an LD of it back, then halt.
        let program = Arc::new(Program::new(
            vec![
                addi(1, 0x2_0003),
                addi(2, 0x1122_3344_5566_7788),
                Instruction::new(Opcode::SD, 2, 1, 0, false, true),
                Instruction::new(Opcode::LD, 3, 1, 0, false, true),
                addi(5, SyscallCode::HALT as u64),
                addi(10, 0),
                ecall(),
            ],
            0x1000,
            0x1000,
        ));
        let mut run = PureRun::new(program, Vec::new(), u64::MAX);
        run.run_interpreted().expect("pure execution runs it");
        assert_eq!(run.registers()[3], 0x1122_3344_5566_7788);
        assert_eq!(run.misaligned_accesses(), 2);
    }
}
