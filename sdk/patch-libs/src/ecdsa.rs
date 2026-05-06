//! An implementation of the types needed for [`CurveArithmetic`].
//!
//! [`CurveArithmetic`] is a trait that is used in [RustCryptos ECDSA](https://github.com/RustCrypto/signatures).
//!
//! [`CurveArithmetic`] contains all the types needed to implement the ECDSA algorithm over some
//! curve.
//!
//! This implementation is specifically for use inside of Pico zkVM, and internally uses Pico's Weierstrass
//! precompiles.
//!
//! In summary, Pico overrides curve arithmetic entirely, and patches upstream field operations
//! to be more efficient in the VM, such as `sqrt` or `inverse`.

use crate::utils::AffinePoint as PicoAffinePointTrait;

use elliptic_curve::{
    ff, generic_array::typenum::consts::U32, subtle::CtOption, CurveArithmetic, FieldBytes,
};
use std::{fmt::Debug, ops::Neg};

/// The affine point type for Pico.
pub mod affine;
pub use affine::AffinePoint;

/// The projective point type for Pico.
pub mod projective;
pub use projective::ProjectivePoint;

/// NOTE: The only supported ECDSA curves are secp256k1 and secp256r1, which both
/// have 8 limbs in their field elements.
const POINT_LIMBS: usize = 4 * 2;

/// The number of bytes in a field element as an [`usize`].
const FIELD_BYTES_SIZE_USIZE: usize = 32;

/// The number of bytes in a field element as an [`elliptic_curve::generic_array::U32`].
#[allow(non_camel_case_types)]
type FIELD_BYTES_SIZE = U32;

/// A [`CurveArithmetic`] extension for Pico acceleration.
///
/// Patched crates implement this trait to take advantage of Pico-specific acceleration in the zkVM
/// context.
///
/// Note: This trait only supports 32 byte base field curves.
pub trait ECDSACurve
where
    Self: CurveArithmetic<
        FieldBytesSize = FIELD_BYTES_SIZE,
        AffinePoint = AffinePoint<Self>,
        ProjectivePoint = ProjectivePoint<Self>,
    >,
{
    type FieldElement: Field<Self> + Neg<Output = Self::FieldElement>;

    /// The underlying [`PicoAffinePointTrait`] implementation.
    type PicoAffinePoint: ECDSAPoint;

    /// The `a` coefficient in the curve equation.
    const EQUATION_A: Self::FieldElement;

    /// The `b` coefficient in the curve equation.
    const EQUATION_B: Self::FieldElement;
}

/// Alias trait for the [`ff::PrimeField`] with 32 byte field elements.
///
/// Note: All bytes should be considered to be in big-endian format.
pub trait Field<C: ECDSACurve>: ff::PrimeField {
    /// Create an instance of self from a FieldBytes.
    fn from_bytes(bytes: &FieldBytes<C>) -> CtOption<Self>;

    /// Convert self to a FieldBytes.
    ///
    /// Note: Implementers should ensure these methods normalize first.
    fn to_bytes(self) -> FieldBytes<C>;

    /// Ensure the field element is normalized.
    fn normalize(self) -> Self;
}

pub type FieldElement<C> = <C as ECDSACurve>::FieldElement;

/// Alias trait for the [`PicoAffinePointTrait`] with 32 byte field elements.
pub trait ECDSAPoint:
    PicoAffinePointTrait<POINT_LIMBS> + Clone + Copy + Debug + Send + Sync
{
    #[inline]
    fn from(x: &[u8], y: &[u8]) -> Self {
        <Self as PicoAffinePointTrait<POINT_LIMBS>>::from(x, y)
    }
}

impl<P> ECDSAPoint for P where
    P: PicoAffinePointTrait<POINT_LIMBS> + Clone + Copy + Debug + Send + Sync
{
}

pub mod ecdh {
    pub use elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret, SharedSecret};

    use super::{AffinePoint, ECDSACurve, Field};

    impl<C: ECDSACurve> From<&AffinePoint<C>> for SharedSecret<C> {
        fn from(affine: &AffinePoint<C>) -> SharedSecret<C> {
            let (x, _) = affine.field_elements();

            x.to_bytes().into()
        }
    }
}
