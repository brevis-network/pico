use super::{Array, Builder, DslIr, Felt, Usize, Var};
use crate::{configs::config::FieldGenericConfig, primitives::consts::NUM_BITS};
use p3_field::PrimeCharacteristicRing;

impl<FC: FieldGenericConfig> Builder<FC> {
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

    /// Convert bits to a variable inside a circuit.
    pub fn bits2num_v_circuit(&mut self, bits: &[Var<FC::N>]) -> Var<FC::N> {
        let result: Var<_> = self.eval(FC::N::ZERO);
        for i in 0..bits.len() {
            self.assign(result, result + bits[i] * FC::N::from_u32(1 << i));
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
}
