use crate::{
    compiler::recursion::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            hash::FieldHasherVariable,
            stark::BaseProofVariable,
            types::FriProofVariable,
        },
        ir::{Builder, Ext, Felt},
    },
    configs::config::{Com, PcsProof},
    machine::{
        proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues},
        septic::{SepticCurve, SepticDigest, SepticExtension},
    },
};
use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::DenseStorage;
use std::sync::Arc;

pub trait WitnessWriter<CC: CircuitConfig>: Sized {
    fn write_bit(&mut self, value: bool);

    fn write_var(&mut self, value: CC::N);

    fn write_felt(&mut self, value: CC::F);

    fn write_ext(&mut self, value: CC::EF);
}

pub trait Witnessable<CC: CircuitConfig> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut impl WitnessWriter<CC>);
}

impl<CC: CircuitConfig> Witnessable<CC> for bool {
    type WitnessVariable = CC::Bit;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        CC::read_bit(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        witness.write_bit(*self);
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for &T {
    type WitnessVariable = T::WitnessVariable;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        (*self).read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        (*self).write(witness)
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>, U: Witnessable<CC>> Witnessable<CC> for (T, U) {
    type WitnessVariable = (T::WitnessVariable, U::WitnessVariable);

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        (self.0.read(builder), self.1.read(builder))
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.0.write(witness);
        self.1.write(witness);
    }
}

macro_rules! impl_witnessable {
    ($base:ident) => {
        impl<CC: CircuitConfig<F = $base>> Witnessable<CC> for $base {
            type WitnessVariable = Felt<CC::F>;

            fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
                CC::read_felt(builder)
            }

            fn write(&self, witness: &mut impl WitnessWriter<CC>) {
                witness.write_felt(*self);
            }
        }

        impl<CC: CircuitConfig<F = $base, EF = BinomialExtensionField<$base, 4>>> Witnessable<CC>
            for BinomialExtensionField<$base, 4>
        {
            type WitnessVariable = Ext<CC::F, CC::EF>;

            fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
                CC::read_ext(builder)
            }

            fn write(&self, witness: &mut impl WitnessWriter<CC>) {
                // vec![Block::from(self.as_base_slice())]
                witness.write_ext(*self);
            }
        }
    };
}

impl_witnessable!(BabyBear);
impl_witnessable!(KoalaBear);

impl<CC: CircuitConfig, T: Witnessable<CC>, const N: usize> Witnessable<CC> for [T; N] {
    type WitnessVariable = [T::WitnessVariable; N];

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        self.iter()
            .map(|x| x.read(builder))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap_or_else(|x: Vec<_>| {
                // Cannot just `.unwrap()` without requiring Debug bounds.
                panic!(
                    "could not coerce vec of len {} into array of len {N}",
                    x.len()
                )
            })
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for &[T] {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        self.iter().map(|x| x.read(builder)).collect()
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        for x in self.iter() {
            x.write(witness);
        }
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for Vec<T> {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        self.as_slice().read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.as_slice().write(witness)
    }
}

impl<CC: CircuitConfig, SC: FieldFriConfigVariable<CC, Val = CC::F, Challenge = CC::EF>>
    Witnessable<CC> for BaseProof<SC>
where
    CC::F: Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    Com<SC>: Witnessable<CC, WitnessVariable = <SC as FieldHasherVariable<CC>>::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
{
    type WitnessVariable = BaseProofVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let commitments = self.commitments.read(builder);
        let opened_values = self.opened_values.read(builder);
        let fri_proof = self.opening_proof.read(builder);
        let log_main_degrees = self.log_main_degrees.to_vec();
        let log_quotient_degrees = self.log_main_degrees.to_vec();
        let main_chip_ordering = (*self.main_chip_ordering).clone();
        let public_values = self.public_values.to_vec().read(builder);

        BaseProofVariable {
            commitments,
            opened_values,
            opening_proof: fri_proof,
            log_main_degrees,
            log_quotient_degrees,
            main_chip_ordering,
            public_values,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.commitments.write(witness);
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
        self.public_values.to_vec().write(witness);
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for BaseCommitments<T>
where
    CC::F: Witnessable<CC>,
    CC::EF: Witnessable<CC>,
{
    type WitnessVariable = BaseCommitments<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let main_commit = self.main_commit.read(builder);
        let permutation_commit = self.permutation_commit.read(builder);
        let quotient_commit = self.quotient_commit.read(builder);
        Self::WitnessVariable {
            main_commit,
            permutation_commit,
            quotient_commit,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.main_commit.write(witness);
        self.permutation_commit.write(witness);
        self.quotient_commit.write(witness);
    }
}

impl<CC: CircuitConfig> Witnessable<CC> for BaseOpenedValues<CC::F, CC::EF>
where
    CC::F: Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
{
    type WitnessVariable = BaseOpenedValues<Felt<CC::F>, Ext<CC::F, CC::EF>>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let chips_opened_values = self
            .chips_opened_values
            .iter()
            .map(|opened_value| (**opened_value).clone())
            .collect_vec();
        let chips_opened_values = chips_opened_values.read(builder);
        let chips_opened_values =
            Arc::from(chips_opened_values.into_iter().map(Arc::new).collect_vec());
        Self::WitnessVariable {
            chips_opened_values,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        let chips_opened_values = self
            .chips_opened_values
            .iter()
            .map(|opened_value| (**opened_value).clone())
            .collect_vec();
        chips_opened_values.to_vec().write(witness);
    }
}

impl<CC: CircuitConfig> Witnessable<CC> for ChipOpenedValues<CC::F, CC::EF>
where
    CC::F: Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
{
    type WitnessVariable = ChipOpenedValues<Felt<CC::F>, Ext<CC::F, CC::EF>>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let preprocessed_local = self.preprocessed_local.read(builder);
        let preprocessed_next = self.preprocessed_next.read(builder);
        let main_local = self.main_local.read(builder);
        let main_next = self.main_next.read(builder);
        let permutation_local = self.permutation_local.read(builder);
        let permutation_next = self.permutation_next.read(builder);
        let quotient = self.quotient.read(builder);
        let global_cumulative_sum = self.global_cumulative_sum.read(builder);
        let regional_cumulative_sum = self.regional_cumulative_sum.read(builder);
        let log_main_degree = self.log_main_degree;
        Self::WitnessVariable {
            preprocessed_local,
            preprocessed_next,
            main_local,
            main_next,
            permutation_local,
            permutation_next,
            quotient,
            global_cumulative_sum,
            regional_cumulative_sum,
            log_main_degree,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.preprocessed_local.write(witness);
        self.preprocessed_next.write(witness);
        self.main_local.write(witness);
        self.main_next.write(witness);
        self.permutation_local.write(witness);
        self.permutation_next.write(witness);
        self.quotient.write(witness);
        self.global_cumulative_sum.write(witness);
        self.regional_cumulative_sum.write(witness);
    }
}

impl<CC: CircuitConfig> Witnessable<CC> for SepticDigest<CC::F>
where
    CC::F: Witnessable<CC, WitnessVariable = Felt<CC::F>>,
{
    type WitnessVariable = SepticDigest<Felt<CC::F>>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let x = self.0.x.0.read(builder);
        let y = self.0.y.0.read(builder);
        SepticDigest(SepticCurve {
            x: SepticExtension(x),
            y: SepticExtension(y),
        })
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.0.x.0.write(witness);
        self.0.y.0.write(witness);
    }
}
