use crate::{
    machine::field::{FieldBehavior, FieldType},
    primitives::consts::{
        PERMUTATION_WIDTH, POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY,
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY,
        POSEIDON2_INTERNAL_MATRIX_DIAG_16_MERSENNE31_SHIFTS,
    },
};
use p3_field::{FieldAlgebra, PrimeField32};

pub(crate) fn apply_m_4<FA>(x: &mut [FA])
where
    FA: FieldAlgebra,
{
    let t01 = x[0].clone() + x[1].clone();
    let t23 = x[2].clone() + x[3].clone();
    let t0123 = t01.clone() + t23.clone();
    let t01123 = t0123.clone() + x[1].clone();
    let t01233 = t0123.clone() + x[3].clone();
    // The order here is important. Need to overwrite x[0] and x[2] after x[1] and x[3].
    x[3] = t01233.clone() + x[0].double(); // 3*x[0] + x[1] + x[2] + 2*x[3]
    x[1] = t01123.clone() + x[2].double(); // x[0] + 2*x[1] + 3*x[2] + x[3]
    x[0] = t01123 + t01; // 2*x[0] + 3*x[1] + x[2] + x[3]
    x[2] = t01233 + t23; // x[0] + x[1] + 2*x[2] + 3*x[3]
}

pub(crate) fn external_linear_layer<FA: FieldAlgebra>(state: &mut [FA; PERMUTATION_WIDTH]) {
    for j in (0..PERMUTATION_WIDTH).step_by(4) {
        apply_m_4(&mut state[j..j + 4]);
    }
    let sums: [FA; 4] = core::array::from_fn(|k| {
        (0..PERMUTATION_WIDTH)
            .step_by(4)
            .map(|j| state[j + k].clone())
            .sum::<FA>()
    });

    for j in 0..PERMUTATION_WIDTH {
        state[j] += sums[j % 4].clone();
    }
}

pub(crate) fn internal_linear_layer<FB: FieldBehavior, FA: FieldAlgebra>(
    state: &mut [FA; PERMUTATION_WIDTH],
) {
    let part_sum: FA = state[1..].iter().cloned().sum();
    let full_sum = part_sum.clone() + state[0].clone();

    // The first three diagonal elements are -2, 1, 2 so we do something custom.
    state[0] = part_sum - state[0].clone();
    state[1] = full_sum.clone() + state[1].clone();
    state[2] = full_sum.clone() + state[2].double();

    let matmul_constants: [FA; PERMUTATION_WIDTH] = match FB::field_type() {
        FieldType::TypeBabyBear => POSEIDON2_INTERNAL_MATRIX_DIAG_16_BABYBEAR_MONTY
            .iter()
            .map(|x| FA::from_wrapped_u32(x.as_canonical_u32()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        FieldType::TypeKoalaBear => POSEIDON2_INTERNAL_MATRIX_DIAG_16_KOALABEAR_MONTY
            .iter()
            .map(|x| FA::from_wrapped_u32(x.as_canonical_u32()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        FieldType::TypeMersenne31 => POSEIDON2_INTERNAL_MATRIX_DIAG_16_MERSENNE31_SHIFTS
            .iter()
            .map(|x| FA::TWO.exp_u64(*x as u64))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        _ => unimplemented!("{:?}", FB::field_type()),
    };

    // For the remaining elements we use multiplication.
    // This could probably be improved slightly by making use of the
    // mul_2exp_u64 and div_2exp_u64 but this would involve porting div_2exp_u64 to FieldAlgebra.
    state
        .iter_mut()
        .zip(matmul_constants)
        .skip(3)
        .for_each(|(val, diag_elem)| {
            *val = full_sum.clone() + val.clone() * diag_elem;
        });
}
