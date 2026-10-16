use num_bigint::BigUint;
use p3_field::{PrimeField, PrimeField32};

/// Returns how many `F` elements can be packed into one `SF` element using base-2^(F::bits())
/// packing, after verifying that the packing is injective.
///
/// Injectivity requires that the maximum packed value `(2^F::bits())^n - 1` is less than
/// `SF::order()`, so distinct input sequences cannot alias after reduction.
pub(crate) fn checked_num_packed_f_elms<F: PrimeField32, SF: PrimeField>() -> usize {
    assert!(
        F::order() < SF::order(),
        "F::order() must be less than SF::order()"
    );

    let num_f_elms = SF::bits() / F::bits();
    let max_packed = BigUint::from(1u64) << (F::bits() * num_f_elms);
    assert!(
        max_packed <= SF::order(),
        "SF::order() too small for injective base-2^{} packing of {} F elements",
        F::bits(),
        num_f_elms,
    );

    num_f_elms
}

/// Pack base-field values into a sponge-field element using base-2^(F::bits()) packing.
///
/// Horner evaluation: `b[0] + b[1]*2^31 + b[2]*2^62 + ...`
pub fn pack_f_to_sf<F: PrimeField32, SF: PrimeField>(buf: &[F]) -> SF {
    let base = SF::from_u64(1u64 << F::bits());
    buf.iter().rev().fold(SF::ZERO, |acc, val| {
        acc * base + SF::from_u32(val.as_canonical_u32())
    })
}
