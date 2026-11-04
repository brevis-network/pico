//! Instruction translation for pure mode.
//!
//! Emits plain register and memory operations on `pico_aot_pure::PureState`, with none of the
//! proving bookkeeping the default translator's helpers carry: no clock, no access metadata, no
//! chunk accounting, no snapshots. `ECALL` goes to the host. Semantics follow `aot-runtime`'s
//! `_no_count` helpers.

use crate::types::{sign_extend_imm32_to_u64, Instruction, Opcode};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashSet;

/// Translates one instruction. Returns the code and whether it ends the block.
pub fn translate(pc: u64, inst: &Instruction, leaders: &HashSet<u64>) -> (TokenStream, bool) {
    match inst.opcode {
        Opcode::JAL => {
            let (rd, imm) = inst.j_type();
            let rd = rd as usize;
            let target = pc.wrapping_add(sign_extend_imm32_to_u64(imm));
            let step = step_to(target, leaders);
            (quote! { emu.link(#rd, #pc); Ok(#step) }, true)
        }
        Opcode::JALR => {
            let (rd, rs1, imm) = inst.i_type();
            let (rd, rs1) = (rd as usize, rs1 as usize);
            let imm = u64::from(imm);
            (
                quote! {
                    let target = emu.jalr(#rd, #rs1, #pc, #imm);
                    Ok(crate::NextStep::Dynamic(target))
                },
                true,
            )
        }
        Opcode::BEQ | Opcode::BNE | Opcode::BLT | Opcode::BGE | Opcode::BLTU | Opcode::BGEU => {
            let (rs1, rs2, imm) = inst.b_type();
            let (rs1, rs2) = (rs1 as usize, rs2 as usize);
            let target = pc.wrapping_add(sign_extend_imm32_to_u64(imm));
            let taken = step_to(target, leaders);
            let fallthrough = step_to(pc.wrapping_add(4), leaders);
            let cond = match inst.opcode {
                Opcode::BEQ => quote! { a == b },
                Opcode::BNE => quote! { a != b },
                Opcode::BLT => quote! { (a as i64) < (b as i64) },
                Opcode::BGE => quote! { (a as i64) >= (b as i64) },
                Opcode::BLTU => quote! { a < b },
                _ => quote! { a >= b },
            };
            (
                quote! {
                    let a = emu.r(#rs1);
                    let b = emu.r(#rs2);
                    if #cond { Ok(#taken) } else { Ok(#fallthrough) }
                },
                true,
            )
        }
        Opcode::ECALL => (
            quote! {
                emu.ecall(#pc)
            },
            true,
        ),
        Opcode::EBREAK => (
            quote! { Err(Fault::Guest { kind: FAULT_BREAKPOINT, value: #pc, detail: 0 }) },
            true,
        ),
        Opcode::UNIMP => (
            quote! { Err(Fault::Guest { kind: FAULT_ILLEGAL, value: #pc, detail: 0 }) },
            true,
        ),
        _ => (normal(pc, inst), false),
    }
}

fn step_to(target: u64, leaders: &HashSet<u64>) -> TokenStream {
    if leaders.contains(&target) {
        let name = format_ident!("block_0x{:08x}", target);
        quote! { crate::NextStep::Direct(#name) }
    } else {
        quote! { crate::NextStep::Dynamic(#target) }
    }
}

/// The `pico_aot_pure` function an ALU opcode computes, by its lowercased name; `None` for an
/// opcode that is not an ALU one.
fn alu_fn(opcode: Opcode) -> Option<proc_macro2::Ident> {
    let alu = matches!(
        opcode,
        Opcode::ADD
            | Opcode::SUB
            | Opcode::XOR
            | Opcode::OR
            | Opcode::AND
            | Opcode::SLL
            | Opcode::SRL
            | Opcode::SRA
            | Opcode::SLT
            | Opcode::SLTU
            | Opcode::ADDW
            | Opcode::SUBW
            | Opcode::SLLW
            | Opcode::SRLW
            | Opcode::SRAW
            | Opcode::MUL
            | Opcode::MULH
            | Opcode::MULHU
            | Opcode::MULHSU
            | Opcode::DIV
            | Opcode::DIVU
            | Opcode::REM
            | Opcode::REMU
            | Opcode::MULW
            | Opcode::DIVW
            | Opcode::DIVUW
            | Opcode::REMW
            | Opcode::REMUW
    );
    alu.then(|| format_ident!("{}", format!("{opcode:?}").to_lowercase()))
}

fn normal(pc: u64, inst: &Instruction) -> TokenStream {
    match inst.opcode {
        Opcode::AUIPC => {
            let (rd, imm) = inst.u_type();
            let rd = rd as usize;
            let value = pc.wrapping_add(sign_extend_imm32_to_u64(imm));
            return quote! { emu.w(#rd, #value); };
        }
        Opcode::LB
        | Opcode::LH
        | Opcode::LW
        | Opcode::LBU
        | Opcode::LHU
        | Opcode::LWU
        | Opcode::LD => {
            let (rd, rs1, imm) = inst.i_type();
            let (rd, rs1, imm) = (rd as usize, rs1 as usize, u64::from(imm));
            let f = format_ident!("{}", format!("{:?}", inst.opcode).to_lowercase());
            return quote! { emu.#f(#rd, #rs1, #imm)?; };
        }
        Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD => {
            let (rs2, rs1, imm) = inst.s_type();
            let (rs2, rs1, imm) = (rs2 as usize, rs1 as usize, u64::from(imm));
            let f = format_ident!("{}", format!("{:?}", inst.opcode).to_lowercase());
            return quote! { emu.#f(#rs2, #rs1, #imm)?; };
        }
        _ => {}
    }

    let Some(f) = alu_fn(inst.opcode) else {
        panic!(
            "pure AOT: unsupported opcode {:?} at PC {:#x}",
            inst.opcode, pc
        );
    };
    let rd = inst.op_a as usize;
    if inst.imm_b && inst.imm_c {
        // Both operands constant, as the default translator folds them: sign-extended immediates.
        let b = sign_extend_imm32_to_u64(inst.op_b);
        let c = sign_extend_imm32_to_u64(inst.op_c);
        quote! { { let b: u64 = #b; let c: u64 = #c; emu.w(#rd, pico_aot_pure::#f(b, c)); } }
    } else if inst.imm_c {
        let rs1 = inst.op_b as usize;
        let imm = u64::from(inst.op_c);
        quote! { { let b = emu.r(#rs1); let c = pico_aot_pure::sext32(#imm); emu.w(#rd, pico_aot_pure::#f(b, c)); } }
    } else {
        let rs1 = inst.op_b as usize;
        let rs2 = inst.op_c as usize;
        quote! { { let b = emu.r(#rs1); let c = emu.r(#rs2); emu.w(#rd, pico_aot_pure::#f(b, c)); } }
    }
}
