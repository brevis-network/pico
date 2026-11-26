use super::{Builder, DslIr, Ext, Felt, Usize, Var, Variable};
use crate::{
    configs::config::FieldGenericConfig,
    machine::field::{FieldBehavior, FieldType},
    primitives::consts::EXTENSION_DEGREE,
};
use p3_field::PrimeCharacteristicRing;
use std::ops::{Add, MulAssign};

impl<FC: FieldGenericConfig> Builder<FC> {
    /// The generator for the field.
    ///
    /// Reference: [p3_koala_bear::KoalaBear]
    pub fn generator(&mut self) -> Felt<FC::F> {
        match FC::F::field_type() {
            FieldType::TypeKoalaBear => self.eval(FC::F::from_u32(3)),
            _ => unimplemented!("Unsupported field type"),
        }
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

    pub fn felts2ext(&mut self, felts: &[Felt<FC::F>]) -> Ext<FC::F, FC::EF> {
        assert_eq!(felts.len(), EXTENSION_DEGREE);
        let out: Ext<FC::F, FC::EF> = self.uninit();
        self.push_op(DslIr::CircuitFelts2Ext(felts.try_into().unwrap(), out));
        out
    }
}
