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
    configs::config::{Com, FieldGenericConfig, PcsProof},
    machine::{
        proof::{BaseCommitments, BaseOpenedValues, BaseProof, ChipOpenedValues},
        septic::{SepticCurve, SepticDigest, SepticExtension},
    },
};
use alloc::sync::Arc;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;

pub trait WitnessWriter<CC: FieldGenericConfig>: Sized {
    fn write_bit(&mut self, value: bool);

    fn write_var(&mut self, value: CC::N);

    fn write_felt(&mut self, value: CC::F);

    fn write_ext(&mut self, value: CC::EF);
}

pub trait Witnessable<CC: FieldGenericConfig> {
    type WitnessVariable;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable;

    fn write(&self, witness: &mut impl WitnessWriter<CC>);
}

// allow witnessing &T instead of just &T
// use T::f to more accurately convey we are utilizing T's impl rather than a dereference that
// doesn't happen with (*self).f
impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for &T {
    type WitnessVariable = T::WitnessVariable;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        T::read(self, builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        T::write(self, witness)
    }
}

// allow witnessing of Arc<T> which is essentially &T
impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for Arc<T> {
    type WitnessVariable = T::WitnessVariable;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        T::read(self, builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        T::write(self, witness)
    }
}

// Base implementations for BabyBear and KoalaBear
//
// TODO: can this be trivially extended to M31?
// TODO: unfortunately we cannot make this generic with F: Field due to Bn254Fr. this should be
//       further investigated
impl<CC: CircuitConfig<F = Self>> Witnessable<CC> for BabyBear {
    type WitnessVariable = Felt<CC::F>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        CC::read_felt(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        witness.write_felt(*self);
    }
}

impl<CC: CircuitConfig<F = Self>> Witnessable<CC> for KoalaBear {
    type WitnessVariable = Felt<CC::F>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        CC::read_felt(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        witness.write_felt(*self);
    }
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

// fully generic extension config for any degree where an extension exists
impl<F: Copy, CC: CircuitConfig<F = F, EF = BinomialExtensionField<F, D>>, const D: usize>
    Witnessable<CC> for BinomialExtensionField<F, D>
{
    type WitnessVariable = Ext<CC::F, CC::EF>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        CC::read_ext(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        witness.write_ext(*self);
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>, const N: usize> Witnessable<CC> for [T; N] {
    type WitnessVariable = [T::WitnessVariable; N];

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        // borrow each entry of the array and then directly map without heap allocating
        self.each_ref().map(|x| x.read(builder))
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

// specialized impls for containers that hold an equivalent of &[T]
impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for Arc<[T]> {
    type WitnessVariable = Vec<T::WitnessVariable>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        self.as_ref().read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.as_ref().write(witness)
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
        let log_main_degrees = self.log_main_degrees.clone();
        let log_quotient_degrees = self.log_main_degrees.clone();
        let main_chip_ordering = self.main_chip_ordering.clone();
        let public_values = self.public_values.read(builder);

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
        self.public_values.write(witness);
    }
}

impl<CC: CircuitConfig, T: Witnessable<CC>> Witnessable<CC> for BaseCommitments<T> {
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
    // directly use the Vec<ChipOpenedValues> to avoid allocating a new Arc
    type WitnessVariable = Vec<ChipOpenedValues<Felt<CC::F>, Ext<CC::F, CC::EF>>>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        self.chips_opened_values.read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.chips_opened_values.write(witness);
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
