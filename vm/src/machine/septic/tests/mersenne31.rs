use super::{super::SepticExtension, utils::*};
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};
use p3_mersenne_31::Mersenne31;

#[test]
fn test_m31_ext_mul() {
    test_ext_mul::<Mersenne31>();
}

#[test]
fn test_m31_ext_inv() {
    test_ext_inv::<Mersenne31>();
}

#[test]
fn test_m31_ext_legendre() {
    test_ext_legendre::<Mersenne31>();
}

#[test]
fn test_m31_ext_sqrt() {
    test_ext_sqrt::<Mersenne31>();
}

#[test]
fn test_m31_ext_z_pow_p() {
    let z = SepticExtension::<Mersenne31>::GENERATOR - SepticExtension::<Mersenne31>::TWO;
    test_ext_z_pow_p(z);
}

#[test]
fn test_m31_ext_z_pow_p2() {
    let z = SepticExtension::<Mersenne31>::GENERATOR - SepticExtension::<Mersenne31>::TWO;
    test_ext_z_pow_p2(z);
}

#[test]
fn test_m31_ext_z_pow_exp() {
    test_ext_z_pow_exp::<Mersenne31>();
}

#[test]
fn test_m31_curve_double() {
    let x: SepticExtension<Mersenne31> = SepticExtension::from_base_slice(
        &[0x2013, 0x2015, 0x2016, 0x2023, 0x2024, 0x2016, 0x2017]
            .map(Mersenne31::from_canonical_u32),
    );
    test_curve_double(x);
}

#[test]
fn test_m31_curve_lift_x() {
    let x: SepticExtension<Mersenne31> = SepticExtension::from_base_slice(
        &[0x2013, 0x2015, 0x2016, 0x2023, 0x2024, 0x2016, 0x1].map(Mersenne31::from_canonical_u32),
    );
    test_curve_lift_x(x);
}

#[test]
fn test_m31_const_points() {
    test_const_points::<Mersenne31>();
}

#[test]
#[ignore]
fn test_m31_curve_simple_sum() {
    test_curve_simple_sum::<Mersenne31>();
}

#[test]
#[ignore]
fn test_m31_curve_parallel_sum() {
    test_curve_parallel_sum::<Mersenne31>();
}
