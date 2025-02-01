use super::{super::SepticExtension, utils::*};
use p3_baby_bear::BabyBear;
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};

#[test]
fn test_bb_ext_mul() {
    test_ext_mul::<BabyBear>();
}

#[test]
fn test_bb_ext_inv() {
    test_ext_inv::<BabyBear>();
}

#[test]
fn test_bb_ext_legendre() {
    test_ext_legendre::<BabyBear>();
}

#[test]
fn test_bb_ext_sqrt() {
    test_ext_sqrt::<BabyBear>();
}

#[test]
fn test_bb_ext_z_pow_p() {
    let z = SepticExtension::<BabyBear>::GENERATOR - SepticExtension::<BabyBear>::TWO;
    test_ext_z_pow_p(z);
}

#[test]
fn test_bb_ext_z_pow_p2() {
    let z = SepticExtension::<BabyBear>::GENERATOR - SepticExtension::<BabyBear>::TWO;
    test_ext_z_pow_p2(z);
}

#[test]
fn test_bb_ext_z_pow_exp() {
    test_ext_z_pow_exp::<BabyBear>();
}

#[test]
fn test_bb_curve_double() {
    let x: SepticExtension<BabyBear> = SepticExtension::from_base_slice(
        &[0x2013, 0x2015, 0x2016, 0x2023, 0x2024, 0x2016, 0x2017].map(BabyBear::from_canonical_u32),
    );
    test_curve_double(x);
}

#[test]
fn test_bb_curve_lift_x() {
    let x: SepticExtension<BabyBear> = SepticExtension::from_base_slice(
        &[0x2013, 0x2015, 0x2016, 0x2023, 0x2024, 0x2016, 0x2017].map(BabyBear::from_canonical_u32),
    );
    test_curve_lift_x(x);
}

#[test]
fn test_bb_const_points() {
    test_const_points::<BabyBear>();
}

#[test]
#[ignore]
fn test_bb_curve_simple_sum() {
    test_curve_simple_sum::<BabyBear>();
}

#[test]
#[ignore]
fn test_bb_curve_parallel_sum() {
    test_curve_parallel_sum::<BabyBear>();
}
