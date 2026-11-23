//! `Blake2bControlChip`: one row per `BLAKE2B_ROUNDS` call.
//!
//! Receives the syscall, checks the buffer pointer, reads `v` and writes it back (one access a
//! dword, at `clk`), reads `m` (at `clk`), and holds the ends of the call's chain of rounds on the
//! `LookupType::Blake2bRound` bus (module docs of [`super`]):
//!
//! - it sends `[chunk, clk, STATE, 0, 0, v_in]`, the vector entering round 0, `v_in` the value
//!   `v` held before the call;
//! - it receives `[chunk, clk, STATE, n, n % 10, v_out]`, the vector after the last round,
//!   `v_out` the value it writes;
//! - it offers `[chunk, clk, MESSAGE, 0, s, m in schedule order s]` for each `s` in `0..10`, with
//!   the multiplicity the number of the call's rounds in that row of the schedule, `q + [s < r]`
//!   for `n = 10 q + r`.
//!
//! # Soundness
//!
//! - `n` is the syscall's `a1`, received as its low u16 limb with the two above it zero (the
//!   Ecall chip zeroes the top one). `q` is range-checked to u16 and `r` is one-hot in `0..10`, so
//!   `10 q + r = n` is an integer identity: `q` and `r` are the quotient and remainder.
//! - `n - 1` and `MAX_ROUNDS_PER_CALL - n` are range-checked to u16, which holds `n` to
//!   `1..=MAX_ROUNDS_PER_CALL`, what the emulator runs: the chip proves no call the emulator would
//!   refuse (a call of no rounds, say, which would otherwise prove as a no-op).
//! - The key `(chunk, clk)` is unique among real rows, as for `KeccakControl`: the syscall
//!   receive balances each row against an ECALL, and ECALL clocks strictly increase along the Cpu
//!   trace. So the chain messages of one call cannot pair with another's (`round` module docs,
//!   soundness step 5).
//! - The message offers are receives, whose multiplicity may be any count; a padding row offers
//!   nothing, since `r` sums to `is_real` and `q` is zero off real rows.
//! - What is written: the words of `v_out` that leave a round row as bytes are pinned there; the
//!   `b` words (4..8) leave it as limbs, so they are range-checked here (`round` soundness step 4).
//!   `v_in` and `m` are memory values, u16 limbs.

use super::{
    round::bus_message, Blake2bControlChip, BUFFER_BYTES, BUS_MESSAGE_TAG, BUS_STATE_TAG,
    MAX_ROUNDS_PER_CALL, MESSAGE_DWORDS, SIGMA, STATE_BYTES, STATE_DWORDS,
};
use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadCols, MemoryWriteCols},
        },
        gadgets::{
            addr_add::AddrAddGadget, code_range::CodeRangeCols, syscall_addr::SyscallAddrGadget,
        },
        precompiles::checked_u64_to_u32,
        utils::pad_rows_fixed,
    },
    compiler::{
        riscv::{opcode::ByteOpcode, program::Program},
        word::Word,
    },
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{Blake2bRoundsEvent, PrecompileEvent},
            SyscallCode,
        },
    },
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::{
    borrow::{Borrow, BorrowMut},
    mem::size_of,
    ops::Range,
};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use pico_derive::AlignedBorrow;

pub const NUM_BLAKE2B_CONTROL_COLS: usize = size_of::<Blake2bControlCols<u8>>();

/// Dwords the call touches: `v`, then `m`.
const BUFFER_DWORDS: usize = STATE_DWORDS + MESSAGE_DWORDS;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Blake2bControlCols<T> {
    pub chunk: T,
    pub clk: T,
    /// The buffer pointer: aligned, `>= 2^16`, and `+ 256` below `2^48`.
    pub ptr: SyscallAddrGadget<T>,
    /// The addresses of the buffer's 32 dwords.
    pub addrs: [AddrAddGadget<T>; BUFFER_DWORDS],
    /// `v`: its value before the call is the access's previous value, the value after it the one
    /// written.
    pub v_access: [MemoryWriteCols<T>; STATE_DWORDS],
    /// `m`, read.
    pub m_access: [MemoryReadCols<T>; MESSAGE_DWORDS],
    /// The round count is `n = 10 q + r`.
    pub q: T,
    /// `r`, one-hot.
    pub r: [T; 10],
    pub is_real: T,
    /// `v` is written back, so it may not lie on the program's code.
    pub code_range: CodeRangeCols<T>,
}

impl<F> BaseAir<F> for Blake2bControlChip<F> {
    fn width(&self) -> usize {
        NUM_BLAKE2B_CONTROL_COLS
    }
}

impl<F: PrimeField32> Blake2bControlChip<F> {
    /// One row per call, with its byte lookups: the pointer and address gadgets, the 32 accesses'
    /// timestamp limbs, the code range, `q`, and the written `b` limbs.
    fn event_to_row(
        event: &Blake2bRoundsEvent,
        code: &Range<u64>,
        blu: &mut impl ByteRecordBehavior,
    ) -> [F; NUM_BLAKE2B_CONTROL_COLS] {
        let mut row = [F::ZERO; NUM_BLAKE2B_CONTROL_COLS];
        let cols: &mut Blake2bControlCols<F> = row.as_mut_slice().borrow_mut();
        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "BLAKE2b rounds clk"));
        cols.ptr.populate(blu, event.ptr, u64::from(BUFFER_BYTES));
        cols.code_range
            .populate(event.ptr, u64::from(STATE_BYTES), code, blu);
        for (i, addr) in cols.addrs.iter_mut().enumerate() {
            addr.populate(blu, event.ptr, 8 * i as u64);
        }
        for (access, record) in cols.v_access.iter_mut().zip(&event.v_records) {
            access.populate(*record, blu);
        }
        for (access, record) in cols.m_access.iter_mut().zip(&event.m_records) {
            access.populate(*record, blu);
        }
        cols.q = F::from_u32(event.rounds / 10);
        blu.add_u16_range_check((event.rounds / 10) as u16);
        blu.add_u16_range_check((event.rounds - 1) as u16);
        blu.add_u16_range_check((MAX_ROUNDS_PER_CALL - event.rounds) as u16);
        cols.r[(event.rounds % 10) as usize] = F::ONE;
        for word in &event.v_out[4..8] {
            for j in 0..4 {
                blu.add_u16_range_check((word >> (16 * j)) as u16);
            }
        }
        cols.is_real = F::ONE;
        row
    }

    fn events(input: &EmulationRecord) -> impl Iterator<Item = &Blake2bRoundsEvent> {
        input
            .get_precompile_events(SyscallCode::BLAKE2B_ROUNDS)
            .iter()
            .map(|(_, event)| {
                let PrecompileEvent::Blake2bRounds(event) = event else {
                    unreachable!()
                };
                event
            })
    }
}

impl<F: PrimeField32> ChipBehavior<F> for Blake2bControlChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Blake2bControl".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let code = input.program.code();
        let mut blu: Vec<ByteLookupEvent> = Vec::new();
        let mut rows: Vec<_> = Self::events(input)
            .map(|event| Self::event_to_row(event, &code, &mut blu))
            .collect();
        blu.into_iter()
            .for_each(|event| output.add_byte_lookup_event(event));
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_BLAKE2B_CONTROL_COLS],
            input.shape_chip_size(&self.name()),
        );
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_BLAKE2B_CONTROL_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let code = input.program.code();
        for event in Self::events(input) {
            Self::event_to_row(event, &code, extra);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::BLAKE2B_ROUNDS)
                .is_empty()
        }
    }

    fn local_only(&self) -> bool {
        true
    }
}

impl<F, CB> Air<CB> for Blake2bControlChip<F>
where
    F: Field,
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Blake2bControlCols<CB::Var> = (*local).borrow();
        let is_real: CB::Expr = local.is_real.into();
        builder.assert_bool(local.is_real);

        // `n = 10 q + r`, `r` one-hot on real rows, nothing on padding ones.
        let mut r_sum = CB::Expr::ZERO;
        let mut r = CB::Expr::ZERO;
        for (j, bit) in local.r.iter().enumerate() {
            builder.assert_bool(*bit);
            let bit: CB::Expr = (*bit).into();
            r_sum += bit.clone();
            r += bit * CB::Expr::from_u32(j as u32);
        }
        builder.assert_eq(r_sum, is_real.clone());
        builder.assert_zero(Into::<CB::Expr>::into(local.q) * (CB::Expr::ONE - is_real.clone()));
        builder.looking_rangecheck(
            ByteOpcode::U16Range,
            local.q,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            CB::Expr::ZERO,
            is_real.clone(),
        );
        let q: CB::Expr = local.q.into();
        let n = q.clone() * CB::Expr::from_u32(10) + r.clone();
        // `n` in `1..=MAX_ROUNDS_PER_CALL`, the calls the emulator runs.
        for bound in [
            n.clone() - CB::Expr::ONE,
            CB::Expr::from_u32(MAX_ROUNDS_PER_CALL) - n.clone(),
        ] {
            builder.looking_rangecheck(
                ByteOpcode::U16Range,
                bound,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                is_real.clone(),
            );
        }

        // The buffer pointer, and `v` (the part written back) off the program's code.
        let ptr =
            SyscallAddrGadget::<CB::F>::eval(builder, BUFFER_BYTES, local.ptr, is_real.clone());
        CodeRangeCols::<CB::F>::eval(
            builder,
            &local.code_range,
            [ptr[0].into(), ptr[1].into()],
            CB::Expr::from_u32(STATE_BYTES),
            is_real.clone(),
        );
        for (i, addr) in local.addrs.iter().enumerate() {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([ptr[0].into(), ptr[1].into(), ptr[2].into(), CB::Expr::ZERO]),
                Word::from(8 * i as u64),
                *addr,
                is_real.clone(),
            );
        }
        for (i, access) in local.v_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk,
                local.addrs[i].value.map(Into::into),
                access,
                local.is_real,
            );
        }
        for (i, access) in local.m_access.iter().enumerate() {
            builder.eval_memory_access(
                local.chunk,
                local.clk,
                local.addrs[STATE_DWORDS + i].value.map(Into::into),
                access,
                local.is_real,
            );
        }
        // The written `b` words, which a round row hands over as limbs it does not pin.
        for access in &local.v_access[4..8] {
            for limb in access.value().0 {
                builder.looking_rangecheck(
                    ByteOpcode::U16Range,
                    limb,
                    CB::Expr::ZERO,
                    CB::Expr::ZERO,
                    CB::Expr::ZERO,
                    is_real.clone(),
                );
            }
        }

        // Receive the syscall: `a0` the buffer, `a1` the round count.
        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_u32(SyscallCode::BLAKE2B_ROUNDS.syscall_id()),
            ptr.map(Into::into),
            [n.clone(), CB::Expr::ZERO, CB::Expr::ZERO],
            local.is_real,
        );

        let chunk: CB::Expr = local.chunk.into();
        let clk: CB::Expr = local.clk.into();
        let state_tag = CB::Expr::from_u32(BUS_STATE_TAG);
        let limbs = |words: &mut dyn Iterator<Item = Word<CB::Var>>| -> Vec<CB::Expr> {
            words.flat_map(|w| w.0.map(Into::into)).collect()
        };
        // Round 0 starts from `v` as it was.
        builder.looking(SymbolicLookup::new(
            bus_message(
                chunk.clone(),
                clk.clone(),
                state_tag.clone(),
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                limbs(&mut local.v_access.iter().map(|a| *a.prev_value())),
            ),
            is_real.clone(),
            LookupType::Blake2bRound,
            LookupScope::Regional,
        ));
        // Round `n` ends at `v` as written.
        builder.looked(SymbolicLookup::new(
            bus_message(
                chunk.clone(),
                clk.clone(),
                state_tag,
                n,
                r,
                limbs(&mut local.v_access.iter().map(|a| *a.value())),
            ),
            is_real,
            LookupType::Blake2bRound,
            LookupScope::Regional,
        ));
        // `m` in each schedule order, once per round in that order: `q` times, and once more for
        // the first `r` orders.
        let m: Vec<Word<CB::Var>> = local.m_access.iter().map(|a| *a.value()).collect();
        for (s, order) in SIGMA.iter().enumerate() {
            let mut multiplicity = q.clone();
            for bit in &local.r[s + 1..] {
                multiplicity += Into::<CB::Expr>::into(*bit);
            }
            builder.looked(SymbolicLookup::new(
                bus_message(
                    chunk.clone(),
                    clk.clone(),
                    CB::Expr::from_u32(BUS_MESSAGE_TAG),
                    CB::Expr::ZERO,
                    CB::Expr::from_u32(s as u32),
                    limbs(&mut order.iter().map(|&j| m[j])),
                ),
                multiplicity,
                LookupType::Blake2bRound,
                LookupScope::Regional,
            ));
        }
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> crate::machine::chip::GpuChipBehavior<F> for Blake2bControlChip<F> {
    /// The GPU prover generates this trace on the host, and adds its byte lookups to the device
    /// table, as for the BLS12-381 G2 chips.
    fn gpu_generate_extra_record_and_main(
        &self,
        _device_id: usize,
        input: &Self::Record,
        _prepared_gpu_events: &crate::instances::preparer::PreparedGpuEvents,
        preallocated_gpu_memory: &mut crate::instances::preparer::PreallocatedGpuMemory,
    ) -> crate::chips::trace::TraceData<'_, F> {
        let mut output = EmulationRecord::default();
        let trace = self.generate_main(input, &mut output);
        crate::instances::preparer::gpu_add_host_byte_lookups(
            std::mem::take(&mut output.byte_lookups),
            preallocated_gpu_memory,
        )
        .expect("BLAKE2b control: adding the byte lookups to the device table failed");
        crate::chips::trace::TraceData::Cpu(trace)
    }

    fn is_active_for_extra_record(
        &self,
        record: &crate::instances::preparer::PreparedGpuEvents,
    ) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            record
                .event_counter
                .get_precompile_event_num(SyscallCode::BLAKE2B_ROUNDS)
                > 0
        }
    }
}
