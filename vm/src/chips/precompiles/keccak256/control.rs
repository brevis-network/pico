//! `KeccakControlChip`: one row per `KECCAK_PERMUTE` syscall.
//!
//! Receives the syscall, checks the state pointer, and performs the 25 u64 reads (at `clk`) and
//! 25 u64 writes (at `clk + 1`) of the permutation state. The permutation itself is proven by
//! `KeccakPermuteChip` (24 rows per permutation); the two meet on the `LookupType::KeccakPermute`
//! bus, on which this chip sends two tagged messages per row, `[chunk, clk, 0, read limbs x100]`
//! and `[chunk, clk, 1, write limbs x100]`, and the compute AIR receives each once per
//! permutation (the input on its first step, the output on its final step). Modelled on
//! `ShaCompressControlChip`.
//!
//! No range checks on the state limbs here: the bus equates them limb-by-limb with the p3 `a`
//! (first step) / `a'''` (final step) columns, which p3 pins to u16 by bit decomposition.

use super::{
    KeccakControlChip, KECCAK_STATE_BUS_INPUT_TAG, KECCAK_STATE_BUS_OUTPUT_TAG, STATE_NUM_WORDS,
};
use crate::{
    chips::{
        chips::{
            byte::event::ByteRecordBehavior,
            riscv_memory::read_write::columns::{MemoryCols, MemoryReadCols, MemoryWriteCols},
        },
        gadgets::{addr_add::AddrAddGadget, syscall_addr::SyscallAddrGadget},
        precompiles::checked_u64_to_u32,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            code::SyscallCode,
            precompiles::{KeccakPermuteEvent, PrecompileEvent},
        },
    },
    iter::PicoIterator,
    machine::{
        builder::{ChipBuilder, ChipLookupBuilder, RiscVMemoryBuilder},
        chip::ChipBehavior,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelSlice;
use pico_derive::AlignedBorrow;
use std::{borrow::BorrowMut, iter::once};

pub const NUM_KECCAK_CONTROL_COLS: usize = size_of::<KeccakControlCols<u8>>();

/// The state is 25 u64 words = 200 bytes.
const STATE_NUM_BYTES: u32 = 200;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct KeccakControlCols<T> {
    /// The chunk this syscall was executed in. Carried on the state bus so the permutation is
    /// pinned to one chunk (`clk` restarts at zero every chunk).
    pub chunk: T,
    pub clk: T,
    /// The state address with alignment validation.
    pub state_addr: SyscallAddrGadget<T>,
    /// Address gadgets for each of the 25 state words.
    pub state_addrs: [AddrAddGadget<T>; STATE_NUM_WORDS],
    /// The pre-permutation state, read at `clk`.
    pub state_read: [MemoryReadCols<T>; STATE_NUM_WORDS],
    /// The post-permutation state, written at `clk + 1`.
    pub state_write: [MemoryWriteCols<T>; STATE_NUM_WORDS],
    pub is_real: T,
}

impl<F: PrimeField32> BaseAir<F> for KeccakControlChip<F> {
    fn width(&self) -> usize {
        NUM_KECCAK_CONTROL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for KeccakControlChip<F> {
    type Program = Program;
    type Record = EmulationRecord;

    fn name(&self) -> String {
        "KeccakControl".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = vec![];

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::KECCAK_PERMUTE) {
            let event = if let PrecompileEvent::KeccakPermute(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_row(event, &mut wrapped_rows, &mut vec![]);
        }

        let mut rows = wrapped_rows.unwrap();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_KECCAK_CONTROL_COLS], log_rows);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_KECCAK_CONTROL_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let events: Vec<_> = input
            .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::KeccakPermute(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let blu_batches = events
            .par_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    self.event_to_row(event, &mut None, &mut blu);
                });
                blu
            })
            .collect();

        output.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::KECCAK_PERMUTE)
                .is_empty()
        }
    }
}

impl<F: PrimeField32> KeccakControlChip<F> {
    /// One row per event. Byte lookups: the two address gadgets (once per event, not once per
    /// round as the old in-AIR gadgets did) and the 50 memory-access timestamp checks; none for
    /// the state limbs (see the module doc). Mirrored by `keccak_control.hpp` on the GPU.
    fn event_to_row(
        &self,
        event: &KeccakPermuteEvent,
        rows: &mut Option<Vec<[F; NUM_KECCAK_CONTROL_COLS]>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let mut row = [F::ZERO; NUM_KECCAK_CONTROL_COLS];
        let cols: &mut KeccakControlCols<F> = row.as_mut_slice().borrow_mut();

        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(checked_u64_to_u32(event.clk, "keccak clk"));
        cols.state_addr
            .populate(blu, event.state_addr, u64::from(STATE_NUM_BYTES));
        for i in 0..STATE_NUM_WORDS {
            cols.state_addrs[i].populate(blu, event.state_addr, 8 * i as u64);
            cols.state_read[i].populate(event.state_read_records[i], blu);
            cols.state_write[i].populate(event.state_write_records[i], blu);
        }
        cols.is_real = F::ONE;

        if rows.as_ref().is_some() {
            rows.as_mut().unwrap().push(row);
        }
    }
}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for KeccakControlChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &KeccakControlCols<CB::Var> = (*local).borrow();

        builder.assert_bool(local.is_real);

        // The state pointer: aligned, >= 2^16, and `+ 200` below 2^48.
        let state_addr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            STATE_NUM_BYTES,
            local.state_addr,
            local.is_real.into(),
        );

        for i in 0..STATE_NUM_WORDS {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    state_addr[0].into(),
                    state_addr[1].into(),
                    state_addr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.state_addrs[i],
                local.is_real.into(),
            );

            // The emulator reads the state at `clk` and writes it back at `clk + 1`
            // (`permute.rs`).
            builder.eval_memory_access(
                local.chunk,
                local.clk,
                local.state_addrs[i].value.map(Into::into),
                &local.state_read[i],
                local.is_real,
            );
            builder.eval_memory_access(
                local.chunk,
                local.clk + CB::Expr::ONE,
                local.state_addrs[i].value.map(Into::into),
                &local.state_write[i],
                local.is_real,
            );
        }

        // Receive the syscall.
        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_u32(SyscallCode::KECCAK_PERMUTE.syscall_id()),
            state_addr.map(Into::into),
            [CB::F::ZERO, CB::F::ZERO, CB::F::ZERO],
            local.is_real,
        );

        // Send the pre- and post-permutation state to `KeccakPermuteChip`, limb by limb (no
        // packing: KoalaBear is smaller than 2^32, so a `lo + 2^16 * hi` pair is not injective),
        // as two tagged messages (one message of both would exceed the logUp message-length
        // limit of 128). Word order `i = 0..25` matches the p3 y-major `(i / 5, i % 5)` on the
        // receiving side.
        //
        // Soundness of splitting into two messages rests on the `(chunk, clk)` key being unique
        // per real row: the syscall receive above balances this row against the Ecall chip's
        // sends, whose `clk` strictly increases along the Cpu trace, so no two real control rows
        // share a key and the input and output messages of one row pair with the same
        // permutation on the other side (its first and its final step, which share the key by
        // the compute AIR's copy constraints). The constant tag keeps the two multisets apart.
        let input_values = once(local.chunk.into())
            .chain(once(local.clk.into()))
            .chain(once(CB::Expr::from_u32(KECCAK_STATE_BUS_INPUT_TAG)))
            .chain(
                local
                    .state_read
                    .iter()
                    .flat_map(|m| m.value().0.into_iter())
                    .map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.looking(SymbolicLookup::new(
            input_values,
            local.is_real.into(),
            LookupType::KeccakPermute,
            LookupScope::Regional,
        ));
        let output_values = once(local.chunk.into())
            .chain(once(local.clk.into()))
            .chain(once(CB::Expr::from_u32(KECCAK_STATE_BUS_OUTPUT_TAG)))
            .chain(
                local
                    .state_write
                    .iter()
                    .flat_map(|m| m.value().0.into_iter())
                    .map(Into::into),
            )
            .collect::<Vec<_>>();
        builder.looking(SymbolicLookup::new(
            output_values,
            local.is_real.into(),
            LookupType::KeccakPermute,
            LookupScope::Regional,
        ));
    }
}
