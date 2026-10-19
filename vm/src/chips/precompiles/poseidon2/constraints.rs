use std::borrow::Borrow;

use super::{columns::Poseidon2Cols, Poseidon2PermuteChip, STATE_NUM_BYTES, STATE_NUM_DWORDS};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{
            addr_add::AddrAddGadget, field_range_check::word_range::FieldWordRangeChecker,
            poseidon2::constraints::eval_poseidon2, syscall_addr::SyscallAddrGadget,
        },
    },
    compiler::word::Word,
    configs::config::Poseidon2Config,
    emulator::riscv::syscalls::SyscallCode,
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, RiscVMemoryBuilder},
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_poseidon2::GenericPoseidon2LinearLayers;

impl<
        F: PrimeField32,
        LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
        Config: Poseidon2Config,
        CB: ChipBuilder<F>,
    > Air<CB> for Poseidon2PermuteChip<F, LinearLayers, Config>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
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
        // NOTE on the alignment half: the gadget's `BitRange(13)` check on `addr[0] / 8` has no
        // match in `ByteChip` for a pointer that is only 4-aligned, so such a call has no
        // provable trace -- measured, an honest call at `0x200004` fails with `Regional
        // cumulative sum is not zero`. The syscall now rejects those pointers up front
        // (`assert_dword_aligned_precompile`, twice, in
        // `syscalls/precompiles/poseidon2/permute.rs`), the way its fp/fp2/ec/edwards/sha256/
        // uint256 siblings do, so the two sides agree and the failure names its cause.
        //
        // What is left of that problem is on the *caller* side: the syscall ABI hands over
        // `*const [u32; 16]` / `*mut [u32; 16]`, which Rust aligns to 4, so the SDK's own hasher
        // has to align its buffers to 8 before this precompile can be reached from a guest. See
        // the note beside the commented-out chip in `instances/chiptype/riscv_chiptype.rs`.
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

        // One address per dword, carried across limbs. A slice helper that adds `i * stride`
        // into limb[0] only cannot be used here: once `limb[0] + i * stride` crosses 2^16 the
        // emitted address leaves the u16 range with no carry into limb[1] and matches no
        // correctly encoded address anywhere in the machine.
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
        let base = CB::F::from_u32(1 << 16);
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

            // Each half must additionally be *canonical*, not merely congruent.
            //
            // The two equations above are equalities between field elements, so they hold just
            // as well for a guest word of `state[j] + p`. The emulator would have reduced that
            // word to `state[j]` (`F::from_u32` is a quotient map, not a checked conversion)
            // and permuted the reduced value, so prover and emulator agree -- but only because
            // both silently discarded the same information. Pinning the memory word to the
            // canonical representative is what makes "the word in guest memory" and "the field
            // element this chip permuted" the same object, which is the property the syscall's
            // matching assertion and the output side below both rely on.
            //
            // `is_real` is asserted boolean at the top of this function, which is the
            // precondition `range_check_u32_limbs` carries (it does not re-assert it). The u16
            // bound on the limbs comes from the `slice_range_check_u16` above -- the comparison
            // reasons about the most significant limb alone and bounds nothing without it.
            FieldWordRangeChecker::<CB::F>::range_check_u32_limbs::<CB>(
                builder,
                word[0].into(),
                word[1].into(),
                local.input_range_checkers[2 * i],
                is_real.into(),
            );
            FieldWordRangeChecker::<CB::F>::range_check_u32_limbs::<CB>(
                builder,
                word[2].into(),
                word[3].into(),
                local.input_range_checkers[2 * i + 1],
                is_real.into(),
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
        // The equality alone does not force the written half to be the *canonical*
        // representative of `state[j]`: the limbs are u16 and their weighted sum is fixed only
        // mod p, which still leaves `state[j] + p` (and sometimes `+ 2p`) inside `[0, 2^32)`.
        // Left there, the prover -- not the permutation -- would choose which of those lands in
        // guest memory. `output_range_checkers` closes it, one per written state word.
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

            // Same preconditions as the input side: `is_real` asserted boolean above, limbs
            // bounded to u16 by the `slice_range_check_u16` on the line above.
            FieldWordRangeChecker::<CB::F>::range_check_u32_limbs::<CB>(
                builder,
                word[0].into(),
                word[1].into(),
                local.output_range_checkers[2 * i],
                is_real.into(),
            );
            FieldWordRangeChecker::<CB::F>::range_check_u32_limbs::<CB>(
                builder,
                word[2].into(),
                word[3].into(),
                local.output_range_checkers[2 * i + 1],
                is_real.into(),
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
            CB::F::from_u32(SyscallCode::POSEIDON2_PERMUTE.syscall_id()),
            input_ptr.map(Into::into),
            output_ptr.map(Into::into),
            is_real,
        );
    }
}
