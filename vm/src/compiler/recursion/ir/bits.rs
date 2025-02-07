use super::{Array, Builder, DslIr, Felt, Usize, Var};
use crate::{
    configs::config::FieldGenericConfig,
    machine::field::{FieldBehavior, FieldType},
    primitives::consts::NUM_BITS,
};
use p3_field::{Field, FieldAlgebra};

impl<FC: FieldGenericConfig> Builder<FC> {
    /// Converts a variable to LE bits.
    pub fn num2bits_v(&mut self, num: Var<FC::N>) -> Array<FC, Var<FC::N>> {
        // This function is only used when the native field is Babybear.
        assert!(FC::N::bits() == NUM_BITS);

        let output = self.dyn_array::<Var<_>>(NUM_BITS);
        self.push_op(DslIr::HintBitsV(output.clone(), num));

        let sum: Var<_> = self.eval(FC::N::ZERO);
        for i in 0..NUM_BITS {
            let bit = self.get(&output, i);
            self.assert_var_eq(bit * (bit - FC::N::ONE), FC::N::ZERO);
            self.assign(sum, sum + bit * FC::N::from_canonical_u32(1 << i));
        }

        self.assert_var_eq(sum, num);

        self.less_than_modulus(output.clone());

        output
    }

    /// Range checks a variable to a certain number of bits.
    pub fn range_check_v(&mut self, num: Var<FC::N>, num_bits: usize) {
        let bits = self.num2bits_v(num);
        self.range(num_bits, bits.len()).for_each(|i, builder| {
            let bit = builder.get(&bits, i);
            builder.assert_var_eq(bit, FC::N::ZERO);
        });
    }

    /// Converts a variable to bits inside a circuit.
    pub fn num2bits_v_circuit(&mut self, num: Var<FC::N>, bits: usize) -> Vec<Var<FC::N>> {
        let mut output = Vec::new();
        for _ in 0..bits {
            output.push(self.uninit());
        }

        self.push_op(DslIr::CircuitNum2BitsV(num, bits, output.clone()));

        output
    }

    /// Converts a felt to bits inside a circuit.
    pub fn num2bits_f_circuit(&mut self, num: Felt<FC::F>) -> Vec<Var<FC::N>> {
        let mut output = Vec::new();
        for _ in 0..NUM_BITS {
            output.push(self.uninit());
        }

        self.push_op(DslIr::CircuitNum2BitsF(num, output.clone()));

        output
    }

    /// Convert bits to a variable.
    pub fn bits2num_v(&mut self, bits: &Array<FC, Var<FC::N>>) -> Var<FC::N> {
        let num: Var<_> = self.eval(FC::N::ZERO);
        let power: Var<_> = self.eval(FC::N::ONE);
        self.range(0, bits.len()).for_each(|i, builder| {
            let bit = builder.get(bits, i);
            builder.assign(num, num + bit * power);
            builder.assign(power, power * FC::N::from_canonical_u32(2));
        });
        num
    }

    /// Convert bits to a variable inside a circuit.
    pub fn bits2num_v_circuit(&mut self, bits: &[Var<FC::N>]) -> Var<FC::N> {
        let result: Var<_> = self.eval(FC::N::ZERO);
        for i in 0..bits.len() {
            self.assign(result, result + bits[i] * FC::N::from_canonical_u32(1 << i));
        }
        result
    }

    /// Reverse a list of bits.
    ///
    /// SAFETY: calling this function with `bit_len` greater [`NUM_BITS`] will result in undefined
    /// behavior.
    ///
    /// Reference: [p3_util::reverse_bits_len]
    pub fn reverse_bits_len(
        &mut self,
        index_bits: &Array<FC, Var<FC::N>>,
        bit_len: impl Into<Usize<FC::N>>,
    ) -> Array<FC, Var<FC::N>> {
        let bit_len = bit_len.into();

        let mut result_bits = self.dyn_array::<Var<_>>(NUM_BITS);
        self.range(0, bit_len).for_each(|i, builder| {
            let index: Var<FC::N> = builder.eval(bit_len - i - FC::N::ONE);
            let entry = builder.get(index_bits, index);
            builder.set_value(&mut result_bits, i, entry);
        });

        let zero = self.eval(FC::N::ZERO);
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
        index_bits: Vec<Var<FC::N>>,
        bit_len: usize,
    ) -> Vec<Var<FC::N>> {
        assert!(bit_len <= NUM_BITS);
        let mut result_bits = Vec::new();
        for i in 0..bit_len {
            let idx = bit_len - i - 1;
            result_bits.push(index_bits[idx]);
        }
        result_bits
    }

    /// Checks that the LE bit decomposition of a number is less than the babybear/koalabear modulus.
    ///
    /// SAFETY: This function assumes that the num_bits values are already verified to be boolean.
    ///
    /// The babybear modulus in LE bits is: 100_000_000_000_000_000_000_000_000_111_1.
    /// To check that the num_bits array is less than that value, we first check if the most
    /// significant bits are all 1.  If it is, then we assert that the other bits are all 0.
    /// The koalabear modulus in LE bits is: 100_000_000_000_000_000_000_000_111_111_1.
    /// To check that the num_bits array is less than that value, we first check if the most
    /// significant bits are all 1.  If it is, then we assert that the other bits are all 0.
    fn less_than_modulus(&mut self, num_bits: Array<FC, Var<FC::N>>) {
        let one: Var<_> = self.eval(FC::N::ONE);
        let zero: Var<_> = self.eval(FC::N::ZERO);

        let one_start_id = match FC::F::field_type() {
            FieldType::TypeBabyBear => 3,
            FieldType::TypeKoalaBear => 0,
            _ => unreachable!(),
        };

        let mut most_sig_bits = one;
        for i in (24 + one_start_id)..NUM_BITS {
            let bit = self.get(&num_bits, i);
            most_sig_bits = self.eval(bit * most_sig_bits);
        }

        let mut sum_least_sig_bits = zero;
        for i in 0..(24 + one_start_id) {
            let bit = self.get(&num_bits, i);
            sum_least_sig_bits = self.eval(bit + sum_least_sig_bits);
        }

        // If the most significant 4 bits are all 1, then check the sum of the least significant
        // bits, else return zero.
        let check: Var<_> =
            self.eval(most_sig_bits * sum_least_sig_bits + (one - most_sig_bits) * zero);
        self.assert_var_eq(check, zero);
    }
}
