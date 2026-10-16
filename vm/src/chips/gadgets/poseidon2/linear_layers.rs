//! Linear layers of the riscv-stage KoalaBear Poseidon2 instance, as the riscv Poseidon2 chip's
//! constraints and trace generation use them.
//!
//! `KoalaBearRiscvLinearLayers` computes exactly the same maps as Plonky3's
//! `GenericPoseidon2LinearLayersKoalaBear`: the external layer is the trait's default
//! `mds_light_permutation`, the internal layer is `1 + Diag(V)` with
//! `V = [-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/8, 1/2^24, -1/2^8, -1/8, -1/16, -1/2^24]`.
//! The only difference is how the `±3` and `±4` lanes are written: a multiplication by the
//! constant instead of the upstream addition chain (`x.double() + x`, `x.double().double()`).
//! Over the field both give the same element; over the AIR's symbolic expressions the constant
//! multiplication is one DAG node per lane where the addition chain is two, and the riscv
//! prover's round-0 zerocheck pays per node. The recursion chips and the Poseidon2 precompile keep
//! the upstream type (`FieldSpecificPoseidon2Config::LinearLayers`).

use p3_field::PrimeCharacteristicRing;
use p3_poseidon2::GenericPoseidon2LinearLayers;

use crate::primitives::consts::PERMUTATION_WIDTH;

/// See the module documentation.
#[derive(Debug, Clone, Copy, Default)]
pub struct KoalaBearRiscvLinearLayers;

impl GenericPoseidon2LinearLayers<PERMUTATION_WIDTH> for KoalaBearRiscvLinearLayers {
    fn internal_linear_layer<R: PrimeCharacteristicRing>(state: &mut [R; PERMUTATION_WIDTH]) {
        // Upstream `InternalLayerBaseParameters::generic_internal_linear_layer`: `state[0]` is
        // handled separately (`V[0] = -2`), every other lane becomes `sum + V[i] * state[i]`.
        let part_sum: R = state[1..].iter().cloned().sum();
        let sum = part_sum.clone() + state[0].clone();
        state[0] = part_sum - state[0].clone();

        let three = R::from_u8(3);
        let four = R::from_u8(4);

        state[1] += sum.clone();
        state[2] = state[2].double() + sum.clone();
        state[3] = state[3].halve() + sum.clone();
        state[4] = sum.clone() + state[4].clone() * three.clone();
        state[5] = sum.clone() + state[5].clone() * four.clone();
        state[6] = sum.clone() - state[6].halve();
        state[7] = sum.clone() - state[7].clone() * three;
        state[8] = sum.clone() - state[8].clone() * four;
        state[9] = state[9].div_2exp_u64(8);
        state[9] += sum.clone();
        state[10] = state[10].div_2exp_u64(3);
        state[10] += sum.clone();
        state[11] = state[11].div_2exp_u64(24);
        state[11] += sum.clone();
        state[12] = state[12].div_2exp_u64(8);
        state[12] = sum.clone() - state[12].clone();
        state[13] = state[13].div_2exp_u64(3);
        state[13] = sum.clone() - state[13].clone();
        state[14] = state[14].div_2exp_u64(4);
        state[14] = sum.clone() - state[14].clone();
        state[15] = state[15].div_2exp_u64(24);
        state[15] = sum - state[15].clone();
    }
}

#[cfg(test)]
mod tests {
    use super::KoalaBearRiscvLinearLayers;
    use crate::primitives::consts::PERMUTATION_WIDTH;
    use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
    use p3_poseidon2::GenericPoseidon2LinearLayers;
    use rand::{rng, RngExt};

    /// Both linear layers agree with Plonky3's on random states, element by element.
    #[test]
    fn riscv_linear_layers_match_upstream() {
        let mut rng = rng();
        for _ in 0..1000 {
            let state: [KoalaBear; PERMUTATION_WIDTH] =
                core::array::from_fn(|_| rng.random::<KoalaBear>());

            let (mut ours, mut upstream) = (state, state);
            KoalaBearRiscvLinearLayers::internal_linear_layer(&mut ours);
            GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut upstream);
            assert_eq!(ours, upstream, "internal layer differs on {state:?}");

            let (mut ours, mut upstream) = (state, state);
            KoalaBearRiscvLinearLayers::external_linear_layer(&mut ours);
            GenericPoseidon2LinearLayersKoalaBear::external_linear_layer(&mut upstream);
            assert_eq!(ours, upstream, "external layer differs on {state:?}");
        }
    }
}
