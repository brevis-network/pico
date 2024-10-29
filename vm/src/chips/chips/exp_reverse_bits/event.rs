use crate::{chips::chips::recursion_memory::MemoryRecord, recursion::air::Block};
use p3_field::PrimeField32;
use p3_util::reverse_bits_len;

#[derive(Debug, Clone)]
pub struct ExpReverseBitsLenEvent<F> {
    /// The clk cycle for the event.
    pub clk: F,

    /// Memory records to keep track of the value stored in the x parameter, and the current bit
    /// of the exponent being scanned.
    pub x: MemoryRecord<F>,
    pub current_bit: MemoryRecord<F>,

    /// The length parameter of the function.
    pub len: F,

    /// The previous accumulator value, needed to compute the current accumulator value.
    pub prev_accum: F,

    /// The current accumulator value.
    pub accum: F,

    /// A pointer to the memory address storing the exponent.
    pub ptr: F,

    /// A pointer to the memory address storing the base.
    pub base_ptr: F,

    /// Which step (in the range 0..len) of the computation we are in.
    pub iteration_num: F,
}

impl<F: PrimeField32> ExpReverseBitsLenEvent<F> {
    /// A way to construct a list of dummy events from input x and clk, used for testing.
    pub fn dummy_from_input(x: F, exponent: u32, len: F, timestamp: F) -> Vec<Self> {
        let mut events = Vec::new();
        let mut new_len = len;
        let mut new_exponent = exponent;
        let mut accum = F::one();

        for i in 0..len.as_canonical_u32() {
            let current_bit = new_exponent % 2;
            let prev_accum = accum;
            accum = prev_accum * prev_accum * if current_bit == 0 { F::one() } else { x };
            events.push(Self {
                clk: timestamp + F::from_canonical_u32(i),
                x: MemoryRecord::new_write(
                    F::one(),
                    Block::from([
                        if i == len.as_canonical_u32() - 1 {
                            accum
                        } else {
                            x
                        },
                        F::zero(),
                        F::zero(),
                        F::zero(),
                    ]),
                    timestamp + F::from_canonical_u32(i),
                    Block::from([x, F::zero(), F::zero(), F::zero()]),
                    timestamp + F::from_canonical_u32(i) - F::one(),
                ),
                current_bit: MemoryRecord::new_read(
                    F::zero(),
                    Block::from([
                        F::from_canonical_u32(current_bit),
                        F::zero(),
                        F::zero(),
                        F::zero(),
                    ]),
                    timestamp + F::from_canonical_u32(i),
                    timestamp + F::from_canonical_u32(i) - F::one(),
                ),
                len: new_len,
                prev_accum,
                accum,
                ptr: F::from_canonical_u32(i),
                base_ptr: F::one(),
                iteration_num: F::from_canonical_u32(i),
            });
            new_exponent /= 2;
            new_len -= F::one();
        }
        assert_eq!(
            accum,
            x.exp_u64(reverse_bits_len(exponent as usize, len.as_canonical_u32() as usize) as u64)
        );
        events
    }
}
