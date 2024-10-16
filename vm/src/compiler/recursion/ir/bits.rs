use crate::recursion::runtime::NUM_BITS;
use p3_field::{AbstractField, Field};

use super::{Array, Builder, Config, DslIr, Felt, Usize, Var};

impl<CF: Config> Builder<CF> {
    /// Converts a variable to LE bits.
    pub fn num2bits_v(&mut self, num: Var<CF::N>) -> Array<CF, Var<CF::N>> {
        // This function is only used when the native field is Babybear.
        assert!(CF::N::bits() == NUM_BITS);

        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        self.push(DslIr::HintBitsV(output.clone(), num));

        let sum: Var<_> = self.eval(CF::N::zero());
        for i in 0..NUM_BITS {
            let bit = self.get(&output, i);
            self.assert_var_eq(bit * (bit - CF::N::one()), CF::N::zero());
            self.assign(sum, sum + bit * CF::N::from_canonical_u32(1 << i));
        }

        self.assert_var_eq(sum, num);

        self.less_than_bb_modulus(output.clone());

        output
    }

    /// Range checks a variable to a certain number of bits.
    pub fn range_check_v(&mut self, num: Var<CF::N>, num_bits: usize) {
        let bits = self.num2bits_v(num);
        self.range(num_bits, bits.len()).for_each(|i, builder| {
            let bit = builder.get(&bits, i);
            builder.assert_var_eq(bit, CF::N::zero());
        });
    }

    /// Converts a variable to bits inside a circuit.
    pub fn num2bits_v_circuit(&mut self, num: Var<CF::N>, bits: usize) -> Vec<Var<CF::N>> {
        let mut output = Vec::new();
        for _ in 0..bits {
            output.push(self.uninit());
        }

        self.push(DslIr::CircuitNum2BitsV(num, bits, output.clone()));

        output
    }

    /// Range checks a felt to a certain number of bits.
    pub fn range_check_f(&mut self, num: Felt<CF::F>, num_bits: usize) {
        let bits = self.num2bits_f(num);
        self.range(num_bits, bits.len()).for_each(|i, builder| {
            let bit = builder.get(&bits, i);
            builder.assert_var_eq(bit, CF::N::zero());
        });
    }

    /// Converts a felt to bits.
    pub fn num2bits_f(&mut self, num: Felt<CF::F>) -> Array<CF, Var<CF::N>> {
        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        self.push(DslIr::HintBitsF(output.clone(), num));

        let sum: Felt<_> = self.eval(CF::F::zero());
        for i in 0..NUM_BITS {
            let bit = self.get(&output, i);
            self.assert_var_eq(bit * (bit - CF::N::one()), CF::N::zero());
            self.if_eq(bit, CF::N::one()).then(|builder| {
                builder.assign(sum, sum + CF::F::from_canonical_u32(1 << i));
            });
        }

        self.assert_felt_eq(sum, num);

        self.less_than_bb_modulus(output.clone());

        output
    }

    /// Converts a felt to bits inside a circuit.
    pub fn num2bits_f_circuit(&mut self, num: Felt<CF::F>) -> Vec<Var<CF::N>> {
        let mut output = Vec::new();
        for _ in 0..NUM_BITS {
            output.push(self.uninit());
        }

        self.push(DslIr::CircuitNum2BitsF(num, output.clone()));

        let output_array = self.vec(output.clone());
        self.less_than_bb_modulus(output_array);

        output
    }

    /// Convert bits to a variable.
    pub fn bits2num_v(&mut self, bits: &Array<CF, Var<CF::N>>) -> Var<CF::N> {
        let num: Var<_> = self.eval(CF::N::zero());
        let power: Var<_> = self.eval(CF::N::one());
        self.range(0, bits.len()).for_each(|i, builder| {
            let bit = builder.get(bits, i);
            builder.assign(num, num + bit * power);
            builder.assign(power, power * CF::N::from_canonical_u32(2));
        });
        num
    }

    /// Convert bits to a variable inside a circuit.
    pub fn bits2num_v_circuit(&mut self, bits: &[Var<CF::N>]) -> Var<CF::N> {
        let result: Var<_> = self.eval(CF::N::zero());
        for i in 0..bits.len() {
            self.assign(result, result + bits[i] * CF::N::from_canonical_u32(1 << i));
        }
        result
    }

    /// Convert bits to a felt.
    pub fn bits2num_f(&mut self, bits: &Array<CF, Var<CF::N>>) -> Felt<CF::F> {
        let num: Felt<_> = self.eval(CF::F::zero());
        for i in 0..NUM_BITS {
            let bit = self.get(bits, i);
            // Add `bit * 2^i` to the sum.
            self.if_eq(bit, CF::N::one()).then(|builder| {
                builder.assign(num, num + CF::F::from_canonical_u32(1 << i));
            });
        }
        num
    }

    /// Reverse a list of bits.
    ///
    /// SAFETY: calling this function with `bit_len` greater [`NUM_BITS`] will result in undefined
    /// behavior.
    ///
    /// Reference: [p3_util::reverse_bits_len]
    pub fn reverse_bits_len(
        &mut self,
        index_bits: &Array<CF, Var<CF::N>>,
        bit_len: impl Into<Usize<CF::N>>,
    ) -> Array<CF, Var<CF::N>> {
        let bit_len = bit_len.into();

        let mut result_bits = self.dyn_array::<Var<_>>(NUM_BITS);
        self.range(0, bit_len).for_each(|i, builder| {
            let index: Var<CF::N> = builder.eval(bit_len - i - CF::N::one());
            let entry = builder.get(index_bits, index);
            builder.set_value(&mut result_bits, i, entry);
        });

        let zero = self.eval(CF::N::zero());
        self.range(bit_len, NUM_BITS).for_each(|i, builder| {
            builder.set_value(&mut result_bits, i, zero);
        });

        result_bits
    }

    /// Reverse a list of bits inside a circuit.
    ///
    /// SAFETY: calling this function with `bit_len` greater [`NUM_BITS`] will result in undefined
    /// behavior.
    ///
    /// Reference: [p3_util::reverse_bits_len]
    pub fn reverse_bits_len_circuit(
        &mut self,
        index_bits: Vec<Var<CF::N>>,
        bit_len: usize,
    ) -> Vec<Var<CF::N>> {
        assert!(bit_len <= NUM_BITS);
        let mut result_bits = Vec::new();
        for i in 0..bit_len {
            let idx = bit_len - i - 1;
            result_bits.push(index_bits[idx]);
        }
        result_bits
    }

    /// Checks that the LE bit decomposition of a number is less than the babybear modulus.
    ///
    /// SAFETY: This function assumes that the num_bits values are already verified to be boolean.
    ///
    /// The babybear modulus in LE bits is: 100_000_000_000_000_000_000_000_000_111_1.
    /// To check that the num_bits array is less than that value, we first check if the most
    /// significant bits are all 1.  If it is, then we assert that the other bits are all 0.
    fn less_than_bb_modulus(&mut self, num_bits: Array<CF, Var<CF::N>>) {
        let one: Var<_> = self.eval(CF::N::one());
        let zero: Var<_> = self.eval(CF::N::zero());

        let mut most_sig_4_bits = one;
        for i in (NUM_BITS - 4)..NUM_BITS {
            let bit = self.get(&num_bits, i);
            most_sig_4_bits = self.eval(bit * most_sig_4_bits);
        }

        let mut sum_least_sig_bits = zero;
        for i in 0..(NUM_BITS - 4) {
            let bit = self.get(&num_bits, i);
            sum_least_sig_bits = self.eval(bit + sum_least_sig_bits);
        }

        // If the most significant 4 bits are all 1, then check the sum of the least significant
        // bits, else return zero.
        let check: Var<_> =
            self.eval(most_sig_4_bits * sum_least_sig_bits + (one - most_sig_4_bits) * zero);
        self.assert_var_eq(check, zero);
    }
}
