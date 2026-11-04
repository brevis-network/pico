//! A guest that reaches every chip family the RISC-V machine proves, and the rows the device
//! derives or stores as exceptions: the fixture device traces are held to the host's on.
//!
//! Inline assembly, as `commit-out-of-range` uses it, keeps what the compiler would fold away:
//!
//! - every ALU opcode and its word and immediate forms, every load and store width, and every
//!   branch kind both taken and not (each branch raises a compare row);
//! - writes to x0 from an add, two loads, a mul and an slt;
//! - div, divu, rem, remu and their word forms on divisor 0, on MIN / -1, and on negative
//!   dividends and divisors (signed division raises derived ADD rows);
//! - 256 back-to-back ECALLs, zero-byte public-value writes, so at a chunk size below that some
//!   chunk opens and closes on an ECALL;
//! - an unconstrained block holding a WRITE ECALL, writes to x10, x11 and x5, and a store to a
//!   word the CPU writes before the block and reads after it, closed by an ECALL whose x10 and x11
//!   differ from the opener's;
//! - a Keccak permutation and a Poseidon2 permutation, which land in deferred records.
//!
//! It reads nothing and commits what it computed. The built ELF ships as
//! `perf/bench_data/rv64/chip-coverage-elf`.

#![no_main]
pico_sdk::entrypoint!(main);

pub fn main() {
    pico_sdk::io::commit(&rv::run());
}

#[cfg(not(target_os = "zkvm"))]
mod rv {
    pub fn run() -> Vec<u64> {
        unreachable!("the fixture's instructions exist only on the zkVM target")
    }
}

#[cfg(target_os = "zkvm")]
mod rv {
    use core::{arch::asm, hint::black_box};
    use pico_sdk::riscv_ecalls::{
        ENTER_UNCONSTRAINED, EXIT_UNCONSTRAINED, KECCAK_PERMUTE, POSEIDON2_PERMUTE, WRITE,
    };

    /// The public-value stream's descriptor: a zero-byte write to it changes nothing.
    const PUBLIC_VALUES_FD: u64 = 3;

    macro_rules! op {
        ($ins:literal, $b:expr, $c:expr) => {{
            let a: u64;
            unsafe {
                asm!(concat!($ins, " {0}, {1}, {2}"), out(reg) a, in(reg) black_box($b), in(reg) black_box($c))
            };
            a
        }};
    }

    macro_rules! op_imm {
        ($ins:literal, $b:expr, $imm:literal) => {{
            let a: u64;
            unsafe { asm!(concat!($ins, " {0}, {1}, ", $imm), out(reg) a, in(reg) black_box($b)) };
            a
        }};
    }

    macro_rules! branch {
        ($ins:literal, $b:expr, $c:expr) => {{
            let taken: u64;
            unsafe {
                asm!(
                    concat!($ins, " {1}, {2}, 2f"),
                    "li {0}, 0",
                    "j 3f",
                    "2:",
                    "li {0}, 1",
                    "3:",
                    out(reg) taken,
                    in(reg) black_box($b),
                    in(reg) black_box($c),
                )
            };
            taken
        }};
    }

    pub fn run() -> Vec<u64> {
        let mut out = Vec::new();
        alu(&mut out);
        memory(&mut out);
        branches(&mut out);
        x0_writes();
        divisions(&mut out);
        back_to_back_ecalls();
        out.push(unconstrained_block());
        precompiles(&mut out);
        out
    }

    fn alu(out: &mut Vec<u64>) {
        let pairs: [(u64, u64); 4] = [
            (0x8000_0000_0000_0001, 0xffff_ffff_ffff_fffe),
            ((-5i64) as u64, 3),
            (0x7fff_ffff, 1),
            (0x1234_5678_9abc_def0, 63),
        ];
        for (b, c) in pairs {
            out.extend([
                op!("add", b, c),
                op!("sub", b, c),
                op!("addw", b, c),
                op!("subw", b, c),
                op!("mul", b, c),
                op!("mulh", b, c),
                op!("mulhu", b, c),
                op!("mulhsu", b, c),
                op!("mulw", b, c),
                op!("xor", b, c),
                op!("or", b, c),
                op!("and", b, c),
                op!("sll", b, c),
                op!("sllw", b, c),
                op!("srl", b, c),
                op!("sra", b, c),
                op!("srlw", b, c),
                op!("sraw", b, c),
                op!("slt", b, c),
                op!("sltu", b, c),
                op_imm!("addi", b, "-2048"),
                op_imm!("addiw", b, "2047"),
                op_imm!("xori", b, "-1"),
                op_imm!("ori", b, "1365"),
                op_imm!("andi", b, "-256"),
                op_imm!("slli", b, "63"),
                op_imm!("srli", b, "1"),
                op_imm!("srai", b, "33"),
                op_imm!("slliw", b, "31"),
                op_imm!("srliw", b, "7"),
                op_imm!("sraiw", b, "31"),
                op_imm!("slti", b, "-1"),
                op_imm!("sltiu", b, "1"),
            ]);
        }
        let upper: u64;
        unsafe { asm!("lui {0}, 0x80000", "auipc {1}, 0", out(reg) upper, out(reg) _) };
        out.push(upper);
    }

    fn memory(out: &mut Vec<u64>) {
        let mut buf = [0u64; 4];
        let p = buf.as_mut_ptr();
        let v = black_box(0x8899_aabb_ccdd_eeffu64);
        unsafe {
            asm!(
                "sd {v}, 0({p})",
                "sw {v}, 8({p})",
                "sh {v}, 12({p})",
                "sb {v}, 15({p})",
                "sb {v}, 16({p})",
                v = in(reg) v,
                p = in(reg) p,
            );
        }
        let (d, w, wu, h, hu, b, bu): (u64, u64, u64, u64, u64, u64, u64);
        unsafe {
            asm!(
                "ld {d}, 0({p})",
                "lw {w}, 4({p})",
                "lwu {wu}, 8({p})",
                "lh {h}, 2({p})",
                "lhu {hu}, 12({p})",
                "lb {b}, 1({p})",
                "lbu {bu}, 15({p})",
                p = in(reg) p,
                d = out(reg) d,
                w = out(reg) w,
                wu = out(reg) wu,
                h = out(reg) h,
                hu = out(reg) hu,
                b = out(reg) b,
                bu = out(reg) bu,
            );
        }
        out.extend([d, w, wu, h, hu, b, bu]);
        out.extend(buf);
    }

    fn branches(out: &mut Vec<u64>) {
        let pairs: [(u64, u64); 3] = [(1, 1), ((-1i64) as u64, 1), (1, (-1i64) as u64)];
        for (b, c) in pairs {
            out.extend([
                branch!("beq", b, c),
                branch!("bne", b, c),
                branch!("blt", b, c),
                branch!("bge", b, c),
                branch!("bltu", b, c),
                branch!("bgeu", b, c),
            ]);
        }
    }

    fn x0_writes() {
        let word = black_box(0x0123_4567_89ab_cdefu64);
        let p = &word as *const u64;
        unsafe {
            asm!("add x0, {0}, {1}", in(reg) black_box(5u64), in(reg) black_box(7u64));
            asm!("ld x0, 0({0})", in(reg) p);
            asm!("lw x0, 4({0})", in(reg) p);
            asm!("mul x0, {0}, {1}", in(reg) black_box(3u64), in(reg) black_box(9u64));
            asm!("slt x0, {0}, {1}", in(reg) black_box(1u64), in(reg) black_box(2u64));
        }
    }

    fn divisions(out: &mut Vec<u64>) {
        let cases: [(u64, u64); 8] = [
            (i64::MIN as u64, u64::MAX),
            (i32::MIN as i64 as u64, u64::MAX),
            (1234, 0),
            (i64::MIN as u64, 0),
            ((-7i64) as u64, 2),
            (7, (-2i64) as u64),
            ((-7i64) as u64, (-2i64) as u64),
            (u64::MAX, 3),
        ];
        for (b, c) in cases {
            out.extend([
                op!("div", b, c),
                op!("divu", b, c),
                op!("rem", b, c),
                op!("remu", b, c),
                op!("divw", b, c),
                op!("divuw", b, c),
                op!("remw", b, c),
                op!("remuw", b, c),
            ]);
        }
    }

    fn back_to_back_ecalls() {
        let byte = 0u8;
        unsafe {
            asm!(
                ".rept 256",
                "ecall",
                ".endr",
                inout("t0") u64::from(WRITE) => _,
                in("a0") PUBLIC_VALUES_FD,
                in("a1") &byte as *const u8,
                in("a2") 0u64,
            );
        }
    }

    /// The word the block writes reads back as it was before the block: the exit rolls the
    /// block's memory and registers back and resumes after the opener with x5 = 0.
    fn unconstrained_block() -> u64 {
        let mut cell = 0u64;
        let p = &mut cell as *mut u64;
        unsafe { core::ptr::write_volatile(p, 7) };
        let opened: u64;
        unsafe {
            asm!(
                "ecall",
                inout("t0") u64::from(ENTER_UNCONSTRAINED) => opened,
                in("a0") 0x11u64,
                in("a1") 0x22u64,
            );
        }
        if opened == 1 {
            let byte = 0u8;
            unsafe {
                core::ptr::write_volatile(p, 9);
                asm!(
                    "ecall",
                    inout("t0") u64::from(WRITE) => _,
                    in("a0") PUBLIC_VALUES_FD,
                    in("a1") &byte as *const u8,
                    in("a2") 0u64,
                );
                asm!(
                    "addi a0, a0, 5",
                    "addi a1, a1, 6",
                    "addi t0, t0, 7",
                    "ecall",
                    inout("a0") 0x33u64 => _,
                    inout("a1") 0x44u64 => _,
                    inout("t0") u64::from(EXIT_UNCONSTRAINED) - 7 => _,
                );
            }
        }
        unsafe { core::ptr::read_volatile(p) }
    }

    /// Eight-byte aligned and canonical KoalaBear words, as the precompile requires.
    #[repr(C, align(8))]
    struct Poseidon2State([u32; 16]);

    fn precompiles(out: &mut Vec<u64>) {
        let mut keccak: [u64; 25] =
            core::array::from_fn(|i| black_box(i as u64 * 0x0101_0101_0101_0101));
        unsafe {
            asm!(
                "ecall",
                inout("t0") u64::from(KECCAK_PERMUTE) => _,
                in("a0") keccak.as_mut_ptr(),
                in("a1") 0u64,
            );
        }
        out.extend_from_slice(&keccak[..4]);

        let input = Poseidon2State(core::array::from_fn(|i| black_box(i as u32 + 1)));
        let mut output = Poseidon2State([0; 16]);
        unsafe {
            asm!(
                "ecall",
                inout("t0") u64::from(POSEIDON2_PERMUTE) => _,
                in("a0") &input as *const Poseidon2State,
                in("a1") &mut output as *mut Poseidon2State,
            );
        }
        out.extend(output.0[..4].iter().map(|&w| u64::from(w)));
    }
}
