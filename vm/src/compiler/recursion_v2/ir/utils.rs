use super::{Array, Builder, DslIr, Ext, Felt, SymbolicExt, Usize, Var, Variable};
use crate::configs::config::FieldGenericConfig;
use p3_field::{AbstractExtensionField, AbstractField};
use std::ops::{Add, Mul, MulAssign};

impl<FC: FieldGenericConfig> Builder<FC> {
    /// The generator for the field.
    ///
    /// Reference: [p3_baby_bear::BabyBear]
    pub fn generator(&mut self) -> Felt<FC::F> {
        self.eval(FC::F::from_canonical_u32(31))
    }

    /// Select a variable based on a condition.
    pub fn select_v(&mut self, cond: Var<FC::N>, a: Var<FC::N>, b: Var<FC::N>) -> Var<FC::N> {
        let c = self.uninit();
        self.push_op(DslIr::CircuitSelectV(cond, a, b, c));
        c
    }

    /// Select a felt based on a condition.
    pub fn select_f(&mut self, cond: Var<FC::N>, a: Felt<FC::F>, b: Felt<FC::F>) -> Felt<FC::F> {
        let c = self.uninit();
        self.push_op(DslIr::CircuitSelectF(cond, a, b, c));
        c
    }

    /// Select an extension based on a condition.
    pub fn select_ef(
        &mut self,
        cond: Var<FC::N>,
        a: Ext<FC::F, FC::EF>,
        b: Ext<FC::F, FC::EF>,
    ) -> Ext<FC::F, FC::EF> {
        let c = self.uninit();
        self.push_op(DslIr::CircuitSelectE(cond, a, b, c));
        c
    }

    /// Exponentiates a variable to a power of two.
    pub fn exp_power_of_2<V: Variable<FC>, E: Into<V::Expression>>(
        &mut self,
        e: E,
        power_log: usize,
    ) -> V
    where
        V::Expression: MulAssign<V::Expression> + Clone,
    {
        let mut e = e.into();
        for _ in 0..power_log {
            e *= e.clone();
        }
        self.eval(e)
    }

    /// Exponentializes a variable to an array of bits in little endian.
    pub fn exp_bits<V>(&mut self, x: V, power_bits: &Array<FC, Var<FC::N>>) -> V
    where
        V::Expression: AbstractField,
        V: Copy + Mul<Output = V::Expression> + Variable<FC>,
    {
        let result = self.eval(V::Expression::one());
        let power_f: V = self.eval(x);
        self.range(0, power_bits.len()).for_each(|i, builder| {
            let bit = builder.get(power_bits, i);
            builder
                .if_eq(bit, FC::N::one())
                .then(|builder| builder.assign(result, result * power_f));
            builder.assign(power_f, power_f * power_f);
        });
        result
    }

    /// Exponentiates a felt to a list of bits in little endian.
    pub fn exp_f_bits(&mut self, x: Felt<FC::F>, power_bits: Vec<Var<FC::N>>) -> Felt<FC::F> {
        let mut result = self.eval(FC::F::one());
        let mut power_f: Felt<_> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_f(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Exponentiates a extension to a list of bits in little endian.
    pub fn exp_e_bits(
        &mut self,
        x: Ext<FC::F, FC::EF>,
        power_bits: Vec<Var<FC::N>>,
    ) -> Ext<FC::F, FC::EF> {
        let mut result = self.eval(SymbolicExt::from_f(FC::EF::one()));
        let mut power_f: Ext<_, _> = self.eval(x);
        for i in 0..power_bits.len() {
            let bit = power_bits[i];
            let tmp = self.eval(result * power_f);
            result = self.select_ef(bit, tmp, result);
            power_f = self.eval(power_f * power_f);
        }
        result
    }

    /// Exponetiates a variable to a list of reversed bits with a given length.
    ///
    /// Reference: [p3_util::reverse_bits_len]
    pub fn exp_reverse_bits_len<V>(
        &mut self,
        x: V,
        power_bits: &Array<FC, Var<FC::N>>,
        bit_len: impl Into<Usize<FC::N>>,
    ) -> V
    where
        V::Expression: AbstractField,
        V: Copy + Mul<Output = V::Expression> + Variable<FC>,
    {
        let result = self.eval(V::Expression::one());
        let power_f: V = self.eval(x);
        let bit_len = bit_len.into().materialize(self);
        let bit_len_plus_one: Var<_> = self.eval(bit_len + FC::N::one());

        self.range(1, bit_len_plus_one).for_each(|i, builder| {
            let index: Var<FC::N> = builder.eval(bit_len - i);
            let bit = builder.get(power_bits, index);
            builder
                .if_eq(bit, FC::N::one())
                .then(|builder| builder.assign(result, result * power_f));
            builder.assign(power_f, power_f * power_f);
        });
        result
    }

    /// A version of `exp_reverse_bits_len` that uses the ExpReverseBitsLen precompile.
    pub fn exp_reverse_bits_len_fast(
        &mut self,
        x: Felt<FC::F>,
        power_bits: &Array<FC, Var<FC::N>>,
        bit_len: impl Into<Usize<FC::N>>,
    ) -> Felt<FC::F> {
        // Instantiate an array of length one and store the value of x.
        let mut x_copy_arr: Array<FC, Felt<FC::F>> = self.dyn_array(1);
        self.set(&mut x_copy_arr, 0, x);

        // Get a pointer to the address holding x.
        let x_copy_arr_ptr = match x_copy_arr {
            Array::Dyn(ptr, _) => ptr,
            _ => panic!("Expected a dynamic array"),
        };

        // Materialize the bit length as a Var.
        let bit_len_var = bit_len.into().materialize(self);
        // Get a pointer to the array of bits in the exponent.
        let ptr = match power_bits {
            Array::Dyn(ptr, _) => ptr,
            _ => panic!("Expected a dynamic array"),
        };

        // Call the DslIR instruction ExpReverseBitsLen, which modifies the memory pointed to by
        // `x_copy_arr_ptr`.
        self.push_op(DslIr::ExpReverseBitsLen(
            x_copy_arr_ptr,
            ptr.address,
            bit_len_var,
        ));

        // Return the value stored at the address pointed to by `x_copy_arr_ptr`.
        self.get(&x_copy_arr, 0)
    }

    /// Exponentiates a variable to a list of bits in little endian.
    pub fn exp_power_of_2_v<V>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: impl Into<Usize<FC::N>>,
    ) -> V
    where
        V: Variable<FC> + Copy + Mul<Output = V::Expression>,
    {
        let mut result: V = self.eval(base);
        let power_log: Usize<_> = power_log.into();
        match power_log {
            Usize::Var(power_log) => {
                self.range(0, power_log)
                    .for_each(|_, builder| builder.assign(result, result * result));
            }
            Usize::Const(power_log) => {
                for _ in 0..power_log {
                    result = self.eval(result * result);
                }
            }
        }
        result
    }

    /// Exponentiates a variable to a list of bits in little endian inside a circuit.
    pub fn exp_power_of_2_v_circuit<V>(
        &mut self,
        base: impl Into<V::Expression>,
        power_log: usize,
    ) -> V
    where
        V: Copy + Mul<Output = V::Expression> + Variable<FC>,
    {
        let mut result: V = self.eval(base);
        for _ in 0..power_log {
            result = self.eval(result * result)
        }
        result
    }

    /// Multiplies `base` by `2^{log_power}`.
    pub fn sll<V>(&mut self, base: impl Into<V::Expression>, shift: Usize<FC::N>) -> V
    where
        V: Variable<FC> + Copy + Add<Output = V::Expression>,
    {
        let result: V = self.eval(base);
        self.range(0, shift)
            .for_each(|_, builder| builder.assign(result, result + result));
        result
    }

    /// Creates an ext from a slice of felts.
    pub fn ext_from_base_slice(&mut self, arr: &[Felt<FC::F>]) -> Ext<FC::F, FC::EF> {
        assert!(arr.len() <= <FC::EF as AbstractExtensionField::<FC::F>>::D);
        let mut res = SymbolicExt::from_f(FC::EF::zero());
        for i in 0..arr.len() {
            res += arr[i] * SymbolicExt::from_f(FC::EF::monomial(i));
        }
        self.eval(res)
    }

    pub fn felts2ext(&mut self, felts: &[Felt<FC::F>]) -> Ext<FC::F, FC::EF> {
        assert_eq!(felts.len(), 4);
        let out: Ext<FC::F, FC::EF> = self.uninit();
        self.push_op(DslIr::CircuitFelts2Ext(felts.try_into().unwrap(), out));
        out
    }

    /// Converts an ext to a slice of felts.
    pub fn ext2felt(&mut self, value: Ext<FC::F, FC::EF>) -> Array<FC, Felt<FC::F>> {
        let result = self.dyn_array(4);
        self.push_op(DslIr::HintExt2Felt(result.clone(), value));

        // Verify that the decomposed extension element is correct.
        let mut reconstructed_ext: Ext<FC::F, FC::EF> = self.constant(FC::EF::zero());
        for i in 0..4 {
            let felt = self.get(&result, i);
            let monomial: Ext<FC::F, FC::EF> = self.constant(FC::EF::monomial(i));
            reconstructed_ext = self.eval(reconstructed_ext + monomial * felt);
        }

        self.assert_ext_eq(reconstructed_ext, value);

        result
    }

    /// Converts an ext to a slice of felts inside a circuit.
    pub fn ext2felt_circuit(&mut self, value: Ext<FC::F, FC::EF>) -> [Felt<FC::F>; 4] {
        let a = self.uninit();
        let b = self.uninit();
        let c = self.uninit();
        let d = self.uninit();
        self.push_op(DslIr::CircuitExt2Felt([a, b, c, d], value));
        [a, b, c, d]
    }
}
