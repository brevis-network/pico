#![allow(clippy::assign_op_pattern)]

use super::{
    columns::{MemoryUnalignedCols, DWORD_BYTES, NUM_MEMORY_UNALIGNED_COLS},
    MemoryUnalignedChip,
};
use crate::{
    chips::{
        chips::riscv_memory::{event::MemoryAccessPosition, read_write::MemoryReadWriteChip},
        gadgets::{code_range::CodeRangeCols, u16_to_u8::U16ToU8Gadget},
    },
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::{borrow::Borrow, iter::once};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};

impl<F: Field> BaseAir<F> for MemoryUnalignedChip<F> {
    fn width(&self) -> usize {
        NUM_MEMORY_UNALIGNED_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for MemoryUnalignedChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &MemoryUnalignedCols<CB::Var> = (*local).borrow();
        let rw = MemoryReadWriteChip::<F>::default();
        let ins = &local.instruction;

        // ---- The instruction, received from the Cpu chip ----
        //
        // The same self-proven flags and the same 17-wide message as `MemoryReadWrite`'s, on the
        // same bus: the Cpu chip sends one message per load or store, and either chip may take it.
        // The multiplicity is the flag sum, which `eval_instruction_flags` makes boolean.
        let is_mem: CB::Expr = rw.is_memory_instruction::<CB>(ins);
        let opcode = rw.eval_instruction_flags::<CB>(builder, ins);
        let mut values: Vec<CB::Expr> = vec![opcode];
        values.extend(
            ins.op_a_val()
                .into_iter()
                .chain(ins.op_b_val())
                .chain(ins.op_c_val())
                .chain(once(ins.op_a_0))
                .map(Into::into),
        );
        values.push(is_mem.clone());
        values.push(local.chunk.into());
        values.push(local.clk.into());
        builder.looked(SymbolicLookup::new(
            values,
            is_mem.clone(),
            LookupType::Memory,
            LookupScope::Regional,
        ));

        // ---- The address ----
        //
        // As in `MemoryReadWrite`: `addr_word` is the low half of `op_b + op_c` through boolean
        // carries, the upper half zero (fail-closed at 2^32), limb 1 a u16 and non-zero, so the
        // access lies in `[2^16, 2^32)`. Limb 0 is bounded by the BitRange(13) check below.
        let op_b = ins.op_b_val();
        let op_c = ins.op_c_val();
        let inv_2_16 = CB::F::from_u32(1 << 16).inverse();
        let k1: CB::Expr = (CB::Expr::ZERO + op_b[0] + op_c[0] - local.addr_word[0]) * inv_2_16;
        builder.assert_bool(k1.clone());
        let k2: CB::Expr =
            (CB::Expr::ZERO + op_b[1] + op_c[1] + k1 - local.addr_word[1]) * inv_2_16;
        builder.assert_bool(k2.clone());
        let k3: CB::Expr = (CB::Expr::ZERO + op_b[2] + op_c[2] + k2) * inv_2_16;
        builder.assert_bool(k3.clone());
        let k4: CB::Expr = (CB::Expr::ZERO + op_b[3] + op_c[3] + k3) * inv_2_16;
        builder.assert_bool(k4);
        builder.looking_rangecheck(
            ByteOpcode::U16Range,
            local.addr_word[1],
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_mem.clone(),
        );
        builder.assert_eq(
            CB::Expr::ZERO + local.addr_limb1_inv * local.addr_word[1],
            is_mem.clone(),
        );

        // ---- The offset in the dword ----
        //
        // One-hot on a real row and all zero on padding. `dword0` is the low limb of the dword's
        // address; the BitRange(13) check on `dword0 / 8` makes it a multiple of 8 below 2^16, so
        // `offset` is exactly `addr mod 8`.
        let o = |k: usize| -> CB::Expr { local.offset[k].into() };
        let mut offset_sum = CB::Expr::ZERO;
        let mut offset_value = CB::Expr::ZERO;
        for (k, flag) in local.offset.iter().enumerate() {
            builder.assert_bool(*flag);
            offset_sum = offset_sum + *flag;
            offset_value = offset_value + o(k) * CB::F::from_u8(k as u8);
        }
        builder.assert_eq(offset_sum, is_mem.clone());
        let dword0: CB::Expr = CB::Expr::ZERO + local.addr_word[0] - offset_value;
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::BitRange as u8),
            dword0.clone() * CB::F::from_u8(8).inverse(),
            CB::Expr::from_u8(13),
            CB::Expr::ZERO,
            is_mem.clone(),
        );

        // ---- Whether the access runs into the next dword ----
        //
        // A byte never does; a halfword does from offset 7, a word from 5, a doubleword from 1.
        // The flags and the offset are both one-hot, so this is boolean.
        let w2: CB::Expr = ins.is_lh + ins.is_lhu + ins.is_sh;
        let w4: CB::Expr = ins.is_lw + ins.is_lwu + ins.is_sw;
        let w8: CB::Expr = ins.is_ld + ins.is_sd;
        let crosses: CB::Expr = w2 * o(7)
            + w4 * (o(5) + o(6) + o(7))
            + w8 * (o(1) + o(2) + o(3) + o(4) + o(5) + o(6) + o(7));
        builder.assert_eq(local.cross, crosses);

        // ---- The next dword's address ----
        //
        // `dword + 8`, carrying into limb 1 exactly when limb 0 is `0xfff8`: `next_carry` is pinned
        // both ways, through its product with `dword0 - 0xfff8` and that difference's inverse.
        // Limb 1 then reaches 2^16 only for a dword past `2^32 - 8`; the U16Range check refuses
        // that, so the next dword's address is canonical too.
        let fff8 = CB::F::from_u32(0xfff8);
        builder.assert_bool(local.next_carry);
        builder.assert_zero((CB::Expr::ZERO + local.next_carry) * (dword0.clone() - fff8));
        builder.assert_eq(
            (dword0.clone() - fff8) * local.next_carry_inv,
            is_mem.clone() - local.next_carry,
        );
        let next0: CB::Expr = dword0.clone() + CB::F::from_u8(8)
            - (CB::Expr::ZERO + local.next_carry) * CB::F::from_u32(1 << 16);
        let next1: CB::Expr = CB::Expr::ZERO + local.addr_word[1] + local.next_carry;
        builder.looking_rangecheck(
            ByteOpcode::U16Range,
            next1.clone(),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            local.cross,
        );

        // ---- The two accesses ----
        //
        // The first at `clk + Memory`, as `MemoryReadWrite`'s; the second at `clk + C`, which a
        // load or store leaves free, and only on a row that crosses.
        builder.eval_memory_access_lite(
            local.chunk,
            local.clk + CB::F::from_u32(MemoryAccessPosition::Memory as u32),
            [
                dword0.clone(),
                CB::Expr::ZERO + local.addr_word[1],
                CB::Expr::ZERO,
            ],
            &local.first,
            is_mem.clone(),
        );
        builder.eval_memory_access_lite(
            local.chunk,
            local.clk + CB::F::from_u32(MemoryAccessPosition::C as u32),
            [next0, next1, CB::Expr::ZERO],
            &local.second,
            local.cross,
        );

        // ---- Bytes ----
        //
        // `w` is the sixteen bytes of the two dwords before the access, and `r` the eight of
        // `op_a`. Each limb is split into a committed low byte and an affine high byte, both
        // U8Range-checked where they are used: the first dword on every row, the second on rows
        // that cross, and `op_a` on stores. Every other byte of `w` and `r` meets only a zero
        // coefficient below.
        let limbs =
            |word: &Word<CB::Var>| -> [CB::Expr; 4] { core::array::from_fn(|i| word[i].into()) };
        let is_store: CB::Expr = rw.is_store_instruction::<CB>(ins);
        let first_bytes = U16ToU8Gadget::<F>::eval_u16_to_u8_safe(
            builder,
            limbs(&local.first.prev_value),
            local.first_bytes,
            is_mem.clone(),
        );
        let second_bytes = U16ToU8Gadget::<F>::eval_u16_to_u8_safe(
            builder,
            limbs(&local.second.prev_value),
            local.second_bytes,
            local.cross.into(),
        );
        let r = U16ToU8Gadget::<F>::eval_u16_to_u8_safe(
            builder,
            limbs(&ins.op_a_value),
            local.value_bytes,
            is_store.clone(),
        );
        let w: Vec<CB::Expr> = first_bytes.into_iter().chain(second_bytes).collect();
        let window_limb = |start: usize| -> CB::Expr {
            w[start].clone() + w[start + 1].clone() * CB::F::from_u16(256)
        };

        // ---- What a load reads ----
        //
        // `seen` is the eight bytes from the address on and `seen_byte` the first of them, each
        // the offset's selection from the window (degree 2). Committed, so that the load equations
        // below stay at degree 3 under the x0 gate.
        for l in 0..4 {
            let mut limb = CB::Expr::ZERO;
            for k in 0..DWORD_BYTES {
                limb = limb + o(k) * window_limb(k + 2 * l);
            }
            builder.assert_eq(local.seen[l], limb);
        }
        let mut seen_byte = CB::Expr::ZERO;
        for k in 0..DWORD_BYTES {
            seen_byte = seen_byte + o(k) * w[k].clone();
        }
        builder.assert_eq(local.seen_byte, seen_byte);

        // `op_a` is the loaded value, sign or zero fill included, as in `MemoryReadWrite`: one
        // equation per limb, where the one-hot flags leave one variant's term live. Stores reduce
        // to `op_a == op_a`, and an x0 destination is not constrained.
        let seen = local.seen;
        let msb: CB::Expr = local.msb.into();
        let fill = |flags: CB::Expr| flags * msb.clone() * CB::Expr::from_u16(0xFFFF);
        let a = ins.op_a_val();
        let lv: [CB::Expr; 4] = [
            (ins.is_lb + ins.is_lbu) * local.seen_byte
                + (ins.is_lh + ins.is_lhu + ins.is_lw + ins.is_lwu + ins.is_ld) * seen[0]
                + ins.is_lb * msb.clone() * CB::Expr::from_u16(0xFF00)
                + is_store.clone() * a[0],
            (ins.is_lw + ins.is_lwu + ins.is_ld) * seen[1]
                + fill(ins.is_lb + ins.is_lh)
                + is_store.clone() * a[1],
            ins.is_ld * seen[2] + fill(ins.is_lb + ins.is_lh + ins.is_lw) + is_store.clone() * a[2],
            ins.is_ld * seen[3] + fill(ins.is_lb + ins.is_lh + ins.is_lw) + is_store.clone() * a[3],
        ];
        let not_x0: CB::Expr = CB::Expr::ONE - ins.op_a_0;
        for (limb, value) in a.into_iter().zip(lv) {
            builder.when(not_x0.clone()).assert_eq(limb, value);
        }
        builder.assert_bool(ins.op_a_0);

        // The sign: bit 15 of `sign_src`, through `MemoryReadWrite`'s U16Range trick
        // (`2 * sign_src - msb * 2^16` is a u16 exactly when `msb` is that bit). On LB `sign_src`
        // is `256 * seen_byte`, whose bit 15 is the byte's bit 7.
        builder
            .when(ins.is_lb)
            .assert_eq(local.sign_src, CB::Expr::from_u32(256) * local.seen_byte);
        builder.when(ins.is_lh).assert_eq(local.sign_src, seen[0]);
        builder.when(ins.is_lw).assert_eq(local.sign_src, seen[1]);
        builder.assert_bool(local.msb);
        builder
            .when(ins.is_lbu + ins.is_lhu + ins.is_lwu + ins.is_ld)
            .assert_zero(local.msb);
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::U16Range as u8),
            CB::Expr::TWO * local.sign_src - local.msb * CB::Expr::from_u32(1 << 16),
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            ins.is_lb + ins.is_lh + ins.is_lw,
        );

        // ---- What a store writes ----
        //
        // Byte `i` of the window becomes byte `i - k` of `op_a` where the offset is `k` and
        // `i - k` is below the store's width, and keeps its value elsewhere. `cov[j]` says whether
        // a store covers its byte `j`: every store its byte 0, SH and wider byte 1, SW and SD bytes
        // 2 and 3, SD the rest. On a load every `cov` is zero, so both dwords keep their values;
        // on a row that does not cross, no byte of the second dword is covered. The written limbs
        // are sums of checked bytes, so they are canonical u16s.
        let cov: [CB::Expr; DWORD_BYTES] = [
            ins.is_sb + ins.is_sh + ins.is_sw + ins.is_sd,
            ins.is_sh + ins.is_sw + ins.is_sd,
            ins.is_sw + ins.is_sd,
            ins.is_sw + ins.is_sd,
            ins.is_sd.into(),
            ins.is_sd.into(),
            ins.is_sd.into(),
            ins.is_sd.into(),
        ];
        let written = |i: usize| -> CB::Expr {
            let mut byte = w[i].clone();
            for k in i.saturating_sub(DWORD_BYTES - 1)..=i.min(DWORD_BYTES - 1) {
                let j = i - k;
                byte = byte + o(k) * cov[j].clone() * (r[j].clone() - w[i].clone());
            }
            byte
        };
        let written_limb = |start: usize| -> CB::Expr {
            written(start) + written(start + 1) * CB::F::from_u16(256)
        };
        for l in 0..4 {
            builder.assert_eq(local.first.access.value[l], written_limb(2 * l));
            builder.assert_eq(
                local.second.access.value[l],
                written_limb(DWORD_BYTES + 2 * l),
            );
        }

        // ---- A store misses the program's code, all its bytes, in either dword ----
        let width = CB::Expr::ZERO
            + ins.is_sb
            + ins.is_sh * CB::F::from_u8(2)
            + ins.is_sw * CB::F::from_u8(4)
            + ins.is_sd * CB::F::from_u8(8);
        CodeRangeCols::<F>::eval(
            builder,
            &local.code_range,
            [local.addr_word[0].into(), local.addr_word[1].into()],
            width,
            is_store,
        );
    }
}
