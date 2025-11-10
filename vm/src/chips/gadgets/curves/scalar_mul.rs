use std::ops::Mul;

use num::BigUint;

use super::{AffinePoint, EllipticCurve};

impl<E: EllipticCurve> AffinePoint<E> {
    pub fn scalar_mul(&self, scalar: &BigUint) -> Self {
        // TODO: this reduction should be performed with the EC group size, not
        // modulo the scalar width. since there is no method to get the scalar
        // width, we can just sacrifice some efficiency and iterate over all the
        // bits.
        // let power_two_modulus = BigUint::one() << E::nb_scalar_bits();
        // let scalar = scalar % &power_two_modulus;
        let mut result = E::ec_neutral();
        let mut temp = self.clone();
        for bit in 0..scalar.bits() {
            if scalar.bit(bit) {
                result = result.map_or_else(|| Some(temp.clone()), |r| Some(&r + &temp));
            }
            temp = &temp + &temp;
        }
        result.expect("Scalar multiplication failed")
    }
}

impl<E: EllipticCurve> Mul<&BigUint> for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn mul(self, scalar: &BigUint) -> AffinePoint<E> {
        self.scalar_mul(scalar)
    }
}

impl<E: EllipticCurve> Mul<BigUint> for &AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn mul(self, scalar: BigUint) -> AffinePoint<E> {
        self.scalar_mul(&scalar)
    }
}

impl<E: EllipticCurve> Mul<BigUint> for AffinePoint<E> {
    type Output = AffinePoint<E>;

    fn mul(self, scalar: BigUint) -> AffinePoint<E> {
        self.scalar_mul(&scalar)
    }
}
