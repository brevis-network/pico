use crate::{
    chips::{
        chips::{
            exp_bits_len::{
                assert_koalabear_field,
                columns::{
                    ExpBitsLenCols, ExpBitsLenPreprocessedCols, LOW_BITS_COUNT,
                    NUM_BITS_MAX_PLUS_ONE, NUM_EXP_BITS_LEN_COLS,
                    NUM_EXP_BITS_LEN_PREPROCESSED_COLS,
                },
                ExpBitsLenChip,
            },
            recursion_memory::MemoryAccessCols,
        },
        utils::pad_rows_fixed,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{Address, ExpBitsLenInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::chip::{ChipBehavior, PreprocessedRows},
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

/// Builds the 32 witnessed rows for a single request over the KoalaBear field
/// (`LOW_BITS_COUNT = 24`).
fn build_block<F: PrimeField32>(
    base: F,
    decomp_src: u32,
    n: usize,
) -> [[F; NUM_EXP_BITS_LEN_COLS]; NUM_BITS_MAX_PLUS_ONE] {
    debug_assert!(n < NUM_BITS_MAX_PLUS_ONE);
    debug_assert!(decomp_src < (1u32 << (NUM_BITS_MAX_PLUS_ONE - 1)));

    // base^(2^step) for step = 0..32.
    let mut bases = [F::ZERO; NUM_BITS_MAX_PLUS_ONE];
    let mut cur = base;
    for slot in bases.iter_mut() {
        *slot = cur;
        cur = cur * cur;
    }

    // Reverse product: results[step] is the exponentiation restricted to set bits at positions
    // `>= step` (and `< n`). results[0] is the final `base^(decomp_src mod 2^n)`.
    let mut results = [F::ONE; NUM_BITS_MAX_PLUS_ONE];
    let mut acc = F::ONE;
    for step in (0..NUM_BITS_MAX_PLUS_ONE - 1).rev() {
        if step < n && ((decomp_src >> step) & 1) == 1 {
            acc *= bases[step];
        }
        results[step] = acc;
    }

    let mut block = [[F::ZERO; NUM_EXP_BITS_LEN_COLS]; NUM_BITS_MAX_PLUS_ONE];
    let mut low_bits_are_zero = true;
    let mut high_bits_all_one = false;
    for step in 0..NUM_BITS_MAX_PLUS_ONE {
        if step == LOW_BITS_COUNT {
            high_bits_all_one = true;
        }

        let shifted = decomp_src >> step;
        let num_bits = n.saturating_sub(step);
        let low_bits_left = LOW_BITS_COUNT.saturating_sub(step);

        let cols: &mut ExpBitsLenCols<F> = block[step].as_mut_slice().borrow_mut();
        cols.bit_idx = F::from_usize(step);
        cols.base = bases[step];
        cols.bit_src = F::from_u32(shifted);
        cols.num_bits = F::from_usize(num_bits);
        cols.apply_bit = F::from_bool(num_bits != 0);
        cols.low_bits_left = F::from_usize(low_bits_left);
        cols.in_low_region = F::from_bool(low_bits_left != 0);
        cols.result = results[step];
        cols.result_multiplier = if num_bits != 0 && (shifted & 1) == 1 {
            bases[step]
        } else {
            F::ONE
        };
        cols.bit_src_mod_2 = F::from_bool((shifted & 1) == 1);
        cols.low_bits_are_zero = F::from_bool(low_bits_are_zero);
        cols.high_bits_all_one = F::from_bool(high_bits_all_one);

        if step < LOW_BITS_COUNT {
            low_bits_are_zero &= (shifted & 1) == 0;
        } else if step + 1 < NUM_BITS_MAX_PLUS_ONE {
            high_bits_all_one &= (shifted & 1) == 1;
        }
    }
    block
}

/// A padding row satisfies the ungated `result_multiplier - 1 = apply_bit * bit * (base - 1)`
/// equation (`result_multiplier = 1`, everything else zero) and contributes no memory lookups.
fn padding_row<F: PrimeField32>() -> [F; NUM_EXP_BITS_LEN_COLS] {
    let mut row = [F::ZERO; NUM_EXP_BITS_LEN_COLS];
    let cols: &mut ExpBitsLenCols<F> = row.as_mut_slice().borrow_mut();
    cols.result = F::ONE;
    cols.result_multiplier = F::ONE;
    row
}

impl<F: PrimeField32> ChipBehavior<F> for ExpBitsLenChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExpBitsLen".to_string()
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().exp_bits_len,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        assert_koalabear_field::<F>();
        let mut rows: Vec<[F; NUM_EXP_BITS_LEN_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExpBitsLen(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &ExpBitsLenInstr<F>| {
                let mut block =
                    vec![[F::ZERO; NUM_EXP_BITS_LEN_PREPROCESSED_COLS]; NUM_BITS_MAX_PLUS_ONE];
                block.iter_mut().enumerate().for_each(|(i, row)| {
                    let cols: &mut ExpBitsLenPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    let is_first = i == 0;
                    let is_last = i == NUM_BITS_MAX_PLUS_ONE - 1;
                    cols.is_first = F::from_bool(is_first);
                    cols.is_last = F::from_bool(is_last);
                    cols.is_real = F::ONE;
                    // Read the input on the first row only (negative mult = read).
                    cols.bit_src_in = MemoryAccessCols {
                        addr: instr.bit_src_in_addr,
                        mult: -F::from_bool(is_first),
                    };
                    // Write the result on the first row only (positive mult = write; the count is
                    // backfilled from `read_counts` in convert.rs `finish()`).
                    cols.result_out = MemoryAccessCols {
                        addr: instr.result_out_addr,
                        mult: instr.result_mult * F::from_bool(is_first),
                    };
                    // Per-row bit output. Rows without a consumer (terminal row, or bits beyond the
                    // requested export width) carry the zero address with mult 0.
                    let (bit_addr, bit_mult) = if i < instr.bit_outs_addrs_mults.len() {
                        instr.bit_outs_addrs_mults[i]
                    } else {
                        (Address(F::ZERO), F::ZERO)
                    };
                    cols.bit_out = MemoryAccessCols {
                        addr: bit_addr,
                        mult: bit_mult,
                    };
                    // Per-request constants, injected on the first row (see the `is_first` anchors).
                    if is_first {
                        cols.base_const = instr.base;
                        cols.num_bits_const = F::from_u32(instr.num_bits);
                    }
                });
                rows.extend(block);
            });

        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_EXP_BITS_LEN_PREPROCESSED_COLS],
            program.fixed_log2_rows(&self.name()),
        );

        Some(RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_EXP_BITS_LEN_PREPROCESSED_COLS,
        ))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        assert_koalabear_field::<F>();
        let mut rows: Vec<[F; NUM_EXP_BITS_LEN_COLS]> = Vec::new();

        for event in input.exp_bits_len_events.iter() {
            let block = build_block(
                event.base,
                event.bit_src.as_canonical_u32(),
                event.num_bits as usize,
            );
            rows.extend(block);
        }

        pad_rows_fixed(
            &mut rows,
            padding_row::<F>,
            input.fixed_log2_rows(&self.name()),
        );

        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_EXP_BITS_LEN_COLS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXP_BITS_LEN_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
