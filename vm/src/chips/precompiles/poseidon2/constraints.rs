use std::borrow::Borrow;

use super::{columns::Poseidon2Cols, Poseidon2PermuteChip, STATE_NUM_BYTES, STATE_NUM_DWORDS};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{
            addr_add::AddrAddGadget, poseidon2::constraints::eval_poseidon2,
            syscall_addr::SyscallAddrGadget,
        },
    },
    compiler::word::Word,
    configs::config::Poseidon2Config,
    emulator::riscv::syscalls::SyscallCode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, RiscVMemoryBuilder},
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::{Air, AirBuilder};
use p3_field::{FieldAlgebra, PrimeField32};
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
        CB: ChipBuilder<F>,
    > Air<CB> for Poseidon2PermuteChip<F, LinearLayers, Config>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<CB::Var, Config> = (*local).borrow();

        let is_real = local.value_cols.is_real;

        // Assert that is_real is a boolean.
        builder.assert_bool(is_real);

        // ── Addresses ────────────────────────────────────────────────────────────────────
        //
        // Both pointers are validated as real 48-bit addresses (3 u16 limbs, 8-byte aligned,
        // `>= 2^16` so they cannot reach the register file, and `+ STATE_NUM_BYTES` still below
        // `2^48`), exactly as every other ported precompile does — see
        // `keccak256/constraint.rs`, `uint256/constraints.rs`,
        // `sha256/extend/controller.rs`. The returned limbs are what goes on both buses below.
        //
        // NOTE on the alignment half: this syscall's emulation does *not* require these pointers
        // to be 8-byte aligned. `covered_dword_range` aligns down and tracks a 4-byte offset,
        // where the fp/fp2/ec/edwards/sha256/uint256 syscalls all call
        // `SyscallContext::assert_dword_aligned_precompile` up front (keccak256 relies on
        // `mr_dword`'s `debug_assert` instead). So a guest passing a 4-aligned pointer emulates
        // fine but cannot be proved: measured, an honest call at `0x200004` fails with
        // `Regional cumulative sum is not zero`, because the gadget's `BitRange(13)` check on
        // `addr[0] / 8` has no match in `ByteChip`. Such a call was unprovable before this commit
        // too, for the reasons this commit fixes, so this is not a regression -- but the two
        // sides should be made to agree, and the cheap option is for the syscall to assert the
        // alignment the way its siblings do.
        let input_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            STATE_NUM_BYTES,
            local.input_memory_ptr,
            is_real.into(),
        );
        let output_ptr = SyscallAddrGadget::<CB::F>::eval(
            builder,
            STATE_NUM_BYTES,
            local.output_memory_ptr,
            is_real.into(),
        );

        // One address per dword, carried across limbs. `eval_memory_access_slice` cannot be used
        // here: it adds `i * stride` into limb[0] only, so once `limb[0] + i * stride` crosses
        // 2^16 the emitted address leaves the u16 range with no carry into limb[1] and matches
        // no correctly encoded address anywhere in the machine.
        for i in 0..STATE_NUM_DWORDS {
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    input_ptr[0].into(),
                    input_ptr[1].into(),
                    input_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.input_addrs[i],
                is_real.into(),
            );
            AddrAddGadget::<CB::F>::eval(
                builder,
                Word([
                    output_ptr[0].into(),
                    output_ptr[1].into(),
                    output_ptr[2].into(),
                    CB::Expr::ZERO,
                ]),
                Word::from(8 * i as u64),
                local.output_addrs[i],
                is_real.into(),
            );
        }

        // ── Memory ───────────────────────────────────────────────────────────────────────
        //
        // One access per dword, at the address just constrained. This mirrors the emulator,
        // which reads the input buffer with `mr_dword_slice` at `input_ptr + 8i` on `clk` and
        // writes the output buffer with `mw_dword_slice` at `output_ptr + 8i` on `clk + 1`.
        for i in 0..STATE_NUM_DWORDS {
            builder.eval_memory_access(
                local.chunk,
                local.clk.into(),
                local.input_addrs[i].value.map(Into::into),
                &local.input_memory[i],
                is_real,
            );
            builder.eval_memory_access(
                local.chunk,
                local.clk.into() + CB::Expr::ONE,
                local.output_addrs[i].value.map(Into::into),
                &local.output_memory[i],
                is_real,
            );
        }

        // ── Input binding ────────────────────────────────────────────────────────────────
        //
        // Dword `i` holds state words `2i` (limbs 0-1) and `2i + 1` (limbs 2-3). The limbs are
        // range checked first: the two equations below only pin weighted sums, so without the
        // u16 checks a non-canonical limb pair could hit the same field element.
        let base = CB::F::from_canonical_u32(1 << 16);
        for i in 0..STATE_NUM_DWORDS {
            let word = *local.input_memory[i].value();
            builder.slice_range_check_u16(&word.0, is_real);
            builder.when(is_real).assert_eq(
                local.value_cols.inputs[2 * i],
                word[0].into() + word[1].into() * base,
            );
            builder.when(is_real).assert_eq(
                local.value_cols.inputs[2 * i + 1],
                word[2].into() + word[3].into() * base,
            );
        }

        let state = eval_poseidon2::<F, CB, LinearLayers, Config>(
            builder,
            &local.value_cols,
            &self.constants,
        );

        // ── Output binding ───────────────────────────────────────────────────────────────
        //
        // `eval_memory_access` puts the written word on the memory bus verbatim and constrains
        // nothing about it, so the equality has to be here or the written state is a free
        // column. Same split as the input side, so all four limbs of every written dword are
        // pinned.
        //
        // NOTE: this does not force the written half to be the *canonical* representative of
        // `state[j]`. The limbs are u16 and their weighted sum is fixed mod p, which still
        // leaves `state[j] + p` (and sometimes `+ 2p`) inside `[0, 2^32)`, so the written word
        // is not unique. Closing that needs a `value < p` check on each written half, which
        // `gadgets/field_range_check/word_range.rs` now provides. It would be needed on both
        // sides: 16 input checkers and 16 output checkers.
        for i in 0..STATE_NUM_DWORDS {
            let word = *local.output_memory[i].value();
            builder.slice_range_check_u16(&word.0, is_real);
            builder
                .when(is_real)
                .assert_eq(state[2 * i].clone(), word[0].into() + word[1].into() * base);
            builder.when(is_real).assert_eq(
                state[2 * i + 1].clone(),
                word[2].into() + word[3].into() * base,
            );
        }

        // ── Syscall ──────────────────────────────────────────────────────────────────────
        //
        // The counterparty is `SyscallChip::precompile()`, which sends `arg1`/`arg2` as 3 u16
        // limbs each. This used to send `[ptr, ptr, ptr]` — the whole pointer replicated into
        // all three limb slots — which balances only for `ptr == 0`.
        builder.looked_syscall(
            local.chunk,
            local.clk,
            CB::F::from_canonical_u32(SyscallCode::POSEIDON2_PERMUTE.syscall_id()),
            input_ptr.map(Into::into),
            output_ptr.map(Into::into),
            is_real,
        );
    }
}
