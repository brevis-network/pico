use super::{super::SepticExtension, utils::*};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_koala_bear::KoalaBear;

#[test]
fn test_kb_ext_mul() {
    test_ext_mul::<KoalaBear>();
}

#[test]
fn test_kb_ext_inv() {
    test_ext_inv::<KoalaBear>();
}

#[test]
fn test_kb_ext_legendre() {
    test_ext_legendre::<KoalaBear>();
}

#[test]
fn test_kb_ext_sqrt() {
    test_ext_sqrt::<KoalaBear>();
}

#[test]
fn test_kb_ext_z_pow_p() {
    let z = SepticExtension::<KoalaBear>::GENERATOR - SepticExtension::<KoalaBear>::from_u8(5);
    test_ext_z_pow_p(z);
}

#[test]
fn test_kb_ext_z_pow_p2() {
    let z = SepticExtension::<KoalaBear>::GENERATOR - SepticExtension::<KoalaBear>::from_u8(5);
    test_ext_z_pow_p2(z);
}

#[test]
fn test_kb_ext_z_pow_exp() {
    test_ext_z_pow_exp::<KoalaBear>();
}

#[test]
fn test_kb_curve_double() {
    let x: SepticExtension<KoalaBear> = SepticExtension::from_basis_coefficients_slice(
        &[0x2013, 0x2015, 0x2016, 0x2023, 0x2024, 0x2016, 0x2017].map(KoalaBear::from_u32),
    )
    .unwrap();
    test_curve_double(x);
}

#[test]
fn test_kb_curve_lift_x() {
    let x: SepticExtension<KoalaBear> = SepticExtension::from_basis_coefficients_slice(
        &[0x2013, 0x2015, 0x2016, 0x2023, 0x2024, 0x2016, 0x1].map(KoalaBear::from_u32),
    )
    .unwrap();
    test_curve_lift_x(x);
}

#[test]
fn test_kb_const_points() {
    test_const_points::<KoalaBear>();
}

#[test]
#[ignore]
fn test_kb_curve_simple_sum() {
    test_curve_simple_sum::<KoalaBear>();
}

#[test]
#[ignore]
fn test_kb_curve_parallel_sum() {
    test_curve_parallel_sum::<KoalaBear>();
}

#[test]
fn test_kb_ext_square_textbook() {
    test_ext_square_mul_textbook::<KoalaBear>();
}

#[test]
fn test_kb_ext_coeffs_signed() {
    test_ext_coeffs_signed_consistent::<KoalaBear>();
}
