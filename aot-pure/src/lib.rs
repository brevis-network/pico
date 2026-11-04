//! The interface between pure-mode AOT code and the host that runs it.
//!
//! Pure mode runs a guest to its halt and keeps only what `execute` reports. The generated code
//! does the register and memory operations itself and hands every `ECALL`, and every pc it has no
//! block for, back to the host through [`PureState`]'s callbacks. It links only this crate, and
//! talks to the host through `#[repr(C)]` types and `extern "C"` functions alone, so it can be
//! built into a dynamic library and loaded by a host built separately.
//!
//! Every guest memory access is checked against [`PureState::mem_len`], and control only moves to
//! a compiled block or back to the host, so a guest cannot reach host memory.

use core::ffi::c_void;

/// The layout of [`PureState`] and [`PureProgram`] and the meaning of the callbacks' returns. A
/// host refuses a program built against another.
pub const ABI_VERSION: u32 = 1;

/// The symbol a pure-mode dynamic library exports: `extern "C" fn() -> *const PureProgram`.
pub const ENTRY_SYMBOL: &str = "pico_pure_program";

/// A callback's return that is not a pc: the guest halted.
pub const NEXT_HALT: u64 = u64::MAX;
/// A callback's return that is not a pc: the host failed, and holds the reason.
pub const NEXT_HOST_ERROR: u64 = u64::MAX - 1;

/// [`PureProgram::run`]'s returns.
pub const EXIT_HALT: u32 = 0;
/// The generated code faulted; [`PureState::fault`] and [`PureState::fault_value`] say how.
pub const EXIT_FAULT: u32 = 1;
/// A callback returned [`NEXT_HOST_ERROR`].
pub const EXIT_HOST_ERROR: u32 = 2;
/// The guest ran [`PureState::max_insns`] instructions without halting.
pub const EXIT_CYCLE_LIMIT: u32 = 3;

// `SOURCE_FINGERPRINT`: a hash of this crate's source, which compiles into every pure-mode
// library. A program records the one it was built against, a host refuses another, and a host
// that caches libraries keys them by it.
include!(concat!(env!("OUT_DIR"), "/fingerprint.rs"));

/// [`PureState::fault`] values (0 is none). An access outside guest memory; the value is the address, the detail the access's `ACCESS_*`.
pub const FAULT_OUT_OF_RANGE: u32 = 1;
/// A misaligned load or store; the value is the address, the detail the access's `ACCESS_*`.
pub const FAULT_MISALIGNED: u32 = 2;
/// An `EBREAK`; the value is its pc.
pub const FAULT_BREAKPOINT: u32 = 3;
/// An `UNIMP`; the value is its pc.
pub const FAULT_ILLEGAL: u32 = 4;

/// [`PureState::fault_detail`] for a memory fault: the access, by its instruction.
pub const ACCESS_LB: u32 = 0;
pub const ACCESS_LH: u32 = 1;
pub const ACCESS_LW: u32 = 2;
pub const ACCESS_LBU: u32 = 3;
pub const ACCESS_LHU: u32 = 4;
pub const ACCESS_LWU: u32 = 5;
pub const ACCESS_LD: u32 = 6;
pub const ACCESS_SB: u32 = 7;
pub const ACCESS_SH: u32 = 8;
pub const ACCESS_SW: u32 = 9;
pub const ACCESS_SD: u32 = 10;

/// A guest run's state, shared by the generated code and the host.
#[repr(C)]
pub struct PureState {
    pub regs: [u64; 32],
    /// Instructions run so far, the generated code's and the host's.
    pub insn_count: u64,
    /// The instruction count past which [`run`] stops the guest with [`EXIT_CYCLE_LIMIT`]; checked
    /// between blocks, so a run may pass it by one block.
    pub max_insns: u64,
    /// Guest memory, `mem_len` bytes from guest address 0. The guest may access `mem_floor` and
    /// up.
    pub mem: *mut u8,
    pub mem_len: u64,
    pub mem_floor: u64,
    /// The host's own state, for its callbacks.
    pub host: *mut c_void,
    /// Runs the `ECALL` at `pc`; returns the next pc, [`NEXT_HALT`] or [`NEXT_HOST_ERROR`].
    pub ecall: unsafe extern "C" fn(state: *mut PureState, pc: u64) -> u64,
    /// Runs the one instruction at `pc`, which no compiled block starts at; returns as `ecall`.
    pub step: unsafe extern "C" fn(state: *mut PureState, pc: u64) -> u64,
    pub fault: u32,
    pub fault_value: u64,
    pub fault_detail: u32,
}

/// A pure-mode program, exported by its dispatch crate.
#[repr(C)]
pub struct PureProgram {
    pub abi_version: u32,
    /// The `SOURCE_FINGERPRINT` of the `pico-aot-pure` the program was built against.
    pub source_fingerprint: u64,
    /// SHA-256 of the ELF the code was generated from.
    pub elf_sha256: [u8; 32],
    /// Runs `state` from `pc` until the guest halts; returns an `EXIT_*` code.
    pub run: unsafe extern "C" fn(state: *mut PureState, pc: u64) -> u32,
}

/// A compiled basic block.
pub type BlockFn = fn(&mut PureState) -> Result<Step, Fault>;

/// Where a block goes next.
pub enum Step {
    Direct(BlockFn),
    Dynamic(u64),
    Halt,
}

/// Why a block stopped short; see the `FAULT_*` and `NEXT_HOST_ERROR` values.
#[derive(Clone, Copy, Debug)]
pub enum Fault {
    Guest { kind: u32, value: u64, detail: u32 },
    Host,
}

/// Runs `state` from `pc` until the guest halts, through `lookup`'s blocks, and through the host's
/// `step` where `lookup` has none. Generic and inlined, so each dispatch crate gets its own loop
/// with its own `lookup` called directly.
#[inline(always)]
pub fn run(state: &mut PureState, pc: u64, lookup: impl Fn(u64) -> Option<BlockFn>) -> u32 {
    let mut next = Step::Dynamic(pc);
    loop {
        next = match next {
            Step::Direct(block) => match block(state) {
                Ok(_) if state.insn_count >= state.max_insns => return EXIT_CYCLE_LIMIT,
                Ok(step) => step,
                Err(fault) => return state.exit_with(fault),
            },
            Step::Dynamic(0) | Step::Halt => return EXIT_HALT,
            Step::Dynamic(pc) => match lookup(pc) {
                Some(block) => Step::Direct(block),
                None => {
                    // SAFETY: the host set `step` and owns what it reads.
                    let next = unsafe { (state.step)(state, pc) };
                    match PureState::host_next(next) {
                        Ok(step) => step,
                        Err(fault) => return state.exit_with(fault),
                    }
                }
            },
        };
    }
}

impl PureState {
    fn exit_with(&mut self, fault: Fault) -> u32 {
        match fault {
            Fault::Guest {
                kind,
                value,
                detail,
            } => {
                self.fault = kind;
                self.fault_value = value;
                self.fault_detail = detail;
                EXIT_FAULT
            }
            Fault::Host => EXIT_HOST_ERROR,
        }
    }

    #[inline(always)]
    fn host_next(next: u64) -> Result<Step, Fault> {
        match next {
            NEXT_HALT => Ok(Step::Halt),
            NEXT_HOST_ERROR => Err(Fault::Host),
            pc => Ok(Step::Dynamic(pc)),
        }
    }

    /// Runs the `ECALL` at `pc` in the host.
    #[inline(always)]
    pub fn ecall(&mut self, pc: u64) -> Result<Step, Fault> {
        // SAFETY: the host set `ecall` and owns what it reads.
        let next = unsafe { (self.ecall)(self, pc) };
        Self::host_next(next)
    }

    #[inline(always)]
    pub fn r(&self, reg: usize) -> u64 {
        self.regs[reg]
    }

    /// Writes `reg`; `x0` stays zero.
    #[inline(always)]
    pub fn w(&mut self, reg: usize, value: u64) {
        if reg != 0 {
            self.regs[reg] = value;
        }
    }

    #[inline(always)]
    fn ea(&self, rs1: usize, imm: u64) -> u64 {
        self.regs[rs1].wrapping_add(sext32(imm))
    }

    /// Checks an access of `width` bytes at `addr` by the instruction `access`: aligned to its
    /// width, and inside memory.
    #[inline(always)]
    fn check(&self, addr: u64, width: u64, access: u32) -> Result<(), Fault> {
        if width > 1 && addr & (width - 1) != 0 {
            return Err(Fault::Guest {
                kind: FAULT_MISALIGNED,
                value: addr,
                detail: access,
            });
        }
        match addr.checked_add(width) {
            Some(end) if addr >= self.mem_floor && end <= self.mem_len => Ok(()),
            _ => Err(Fault::Guest {
                kind: FAULT_OUT_OF_RANGE,
                value: addr,
                detail: access,
            }),
        }
    }

    #[inline(always)]
    fn load<T: Copy>(&self, addr: u64) -> T {
        // SAFETY: the caller checked `addr` against `mem_len`.
        unsafe { core::ptr::read_unaligned(self.mem.add(addr as usize) as *const T) }
    }

    #[inline(always)]
    fn store<T: Copy>(&mut self, addr: u64, value: T) {
        // SAFETY: the caller checked `addr` against `mem_len`.
        unsafe { core::ptr::write_unaligned(self.mem.add(addr as usize) as *mut T, value) }
    }

    #[inline(always)]
    pub fn lb(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 1, ACCESS_LB)?;
        self.w(rd, self.load::<u8>(addr) as i8 as i64 as u64);
        Ok(())
    }

    #[inline(always)]
    pub fn lbu(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 1, ACCESS_LBU)?;
        self.w(rd, u64::from(self.load::<u8>(addr)));
        Ok(())
    }

    #[inline(always)]
    pub fn lh(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 2, ACCESS_LH)?;
        self.w(rd, self.load::<u16>(addr) as i16 as i64 as u64);
        Ok(())
    }

    #[inline(always)]
    pub fn lhu(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 2, ACCESS_LHU)?;
        self.w(rd, u64::from(self.load::<u16>(addr)));
        Ok(())
    }

    #[inline(always)]
    pub fn lw(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 4, ACCESS_LW)?;
        self.w(rd, self.load::<u32>(addr) as i32 as i64 as u64);
        Ok(())
    }

    #[inline(always)]
    pub fn lwu(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 4, ACCESS_LWU)?;
        self.w(rd, u64::from(self.load::<u32>(addr)));
        Ok(())
    }

    #[inline(always)]
    pub fn ld(&mut self, rd: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 8, ACCESS_LD)?;
        self.w(rd, self.load::<u64>(addr));
        Ok(())
    }

    #[inline(always)]
    pub fn sb(&mut self, rs2: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 1, ACCESS_SB)?;
        self.store(addr, self.regs[rs2] as u8);
        Ok(())
    }

    #[inline(always)]
    pub fn sh(&mut self, rs2: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 2, ACCESS_SH)?;
        self.store(addr, self.regs[rs2] as u16);
        Ok(())
    }

    #[inline(always)]
    pub fn sw(&mut self, rs2: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 4, ACCESS_SW)?;
        self.store(addr, self.regs[rs2] as u32);
        Ok(())
    }

    #[inline(always)]
    pub fn sd(&mut self, rs2: usize, rs1: usize, imm: u64) -> Result<(), Fault> {
        let addr = self.ea(rs1, imm);
        self.check(addr, 8, ACCESS_SD)?;
        self.store(addr, self.regs[rs2]);
        Ok(())
    }

    /// `rd = pc + 4`, for `JAL`.
    #[inline(always)]
    pub fn link(&mut self, rd: usize, pc: u64) {
        self.w(rd, pc.wrapping_add(4));
    }

    /// `JALR`: `rd = pc + 4`, reading rs1 first; returns `(rs1 + imm) & !1`.
    #[inline(always)]
    pub fn jalr(&mut self, rd: usize, rs1: usize, pc: u64, imm: u64) -> u64 {
        let base = self.regs[rs1];
        self.w(rd, pc.wrapping_add(4));
        base.wrapping_add(sext32(imm)) & !1
    }
}

/// A 32-bit immediate, sign-extended.
#[inline(always)]
pub const fn sext32(imm: u64) -> u64 {
    (imm as u32 as i32 as i64) as u64
}

/// A word result, sign-extended into the register.
#[inline(always)]
pub const fn sext_word(value: u64) -> u64 {
    (value as u32 as i32 as i64) as u64
}

#[inline(always)]
pub fn mulh(lhs: u64, rhs: u64) -> u64 {
    (((lhs as i64) as i128).wrapping_mul((rhs as i64) as i128) >> 64) as u64
}

#[inline(always)]
pub fn mulhu(lhs: u64, rhs: u64) -> u64 {
    ((lhs as u128).wrapping_mul(rhs as u128) >> 64) as u64
}

#[inline(always)]
pub fn mulhsu(lhs: u64, rhs: u64) -> u64 {
    (((lhs as i64) as i128).wrapping_mul(rhs as i128) >> 64) as u64
}

#[inline(always)]
pub fn div(lhs: u64, rhs: u64) -> u64 {
    let (lhs, rhs) = (lhs as i64, rhs as i64);
    if rhs == 0 {
        u64::MAX
    } else if lhs == i64::MIN && rhs == -1 {
        i64::MIN as u64
    } else {
        lhs.wrapping_div(rhs) as u64
    }
}

#[inline(always)]
pub fn divu(lhs: u64, rhs: u64) -> u64 {
    lhs.checked_div(rhs).unwrap_or(u64::MAX)
}

#[inline(always)]
pub fn rem(lhs: u64, rhs: u64) -> u64 {
    let (lhs, rhs) = (lhs as i64, rhs as i64);
    if rhs == 0 {
        lhs as u64
    } else if lhs == i64::MIN && rhs == -1 {
        0
    } else {
        lhs.wrapping_rem(rhs) as u64
    }
}

#[inline(always)]
pub fn remu(lhs: u64, rhs: u64) -> u64 {
    if rhs == 0 {
        lhs
    } else {
        lhs % rhs
    }
}

#[inline(always)]
pub fn divw(lhs: u64, rhs: u64) -> u64 {
    let (lhs, rhs) = (lhs as u32 as i32, rhs as u32 as i32);
    let value = if rhs == 0 {
        -1
    } else if lhs == i32::MIN && rhs == -1 {
        i32::MIN
    } else {
        lhs.wrapping_div(rhs)
    };
    sext_word(value as u32 as u64)
}

#[inline(always)]
pub fn divuw(lhs: u64, rhs: u64) -> u64 {
    let (lhs, rhs) = (lhs as u32, rhs as u32);
    sext_word(u64::from(lhs.checked_div(rhs).unwrap_or(u32::MAX)))
}

#[inline(always)]
pub fn remw(lhs: u64, rhs: u64) -> u64 {
    let (lhs, rhs) = (lhs as u32 as i32, rhs as u32 as i32);
    let value = if rhs == 0 {
        lhs
    } else if lhs == i32::MIN && rhs == -1 {
        0
    } else {
        lhs.wrapping_rem(rhs)
    };
    sext_word(value as u32 as u64)
}

#[inline(always)]
pub fn remuw(lhs: u64, rhs: u64) -> u64 {
    let (lhs, rhs) = (lhs as u32, rhs as u32);
    sext_word(u64::from(if rhs == 0 { lhs } else { lhs % rhs }))
}

macro_rules! alu {
    ($($(#[$doc:meta])* $name:ident($b:ident, $c:ident) $body:expr;)*) => {$(
        $(#[$doc])*
        #[inline(always)]
        pub fn $name($b: u64, $c: u64) -> u64 {
            $body
        }
    )*};
}

// The ALU instructions by their `pico-vm` opcode's lowercased name, for the generated code and
// the host's interpreter alike.
alu! {
    add(b, c) b.wrapping_add(c);
    sub(b, c) b.wrapping_sub(c);
    xor(b, c) b ^ c;
    or(b, c) b | c;
    and(b, c) b & c;
    sll(b, c) b.wrapping_shl((c & 0x3f) as u32);
    srl(b, c) b.wrapping_shr((c & 0x3f) as u32);
    sra(b, c) ((b as i64).wrapping_shr((c & 0x3f) as u32)) as u64;
    slt(b, c) u64::from((b as i64) < (c as i64));
    sltu(b, c) u64::from(b < c);
    mul(b, c) b.wrapping_mul(c);
    addw(b, c) sext_word(u64::from((b as u32).wrapping_add(c as u32)));
    subw(b, c) sext_word(u64::from((b as u32).wrapping_sub(c as u32)));
    sllw(b, c) sext_word(u64::from((b as u32).wrapping_shl((c & 0x1f) as u32)));
    srlw(b, c) sext_word(u64::from((b as u32).wrapping_shr((c & 0x1f) as u32)));
    sraw(b, c) sext_word((b as u32 as i32).wrapping_shr((c & 0x1f) as u32) as u32 as u64);
    mulw(b, c) sext_word(u64::from((b as u32).wrapping_mul(c as u32)));
}
