//! Elliptic Curve `y^2 = x^3 + 2x + 26z^5` over the `F_{p^7} = F_p[z]/(z^7 - 2z - 5)` extension field.

use super::{
    fields::{babybear, koalabear, mersenne31},
    FieldSepticCurve, SepticExtension,
};
use crate::{
    machine::field::{same_field, FieldBehavior, FieldType},
    primitives::Poseidon2Init,
};
use p3_baby_bear::BabyBear;
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::Permutation;
use serde::{Deserialize, Serialize};
use std::{any::Any, ops::Add};

/// A septic elliptic curve point on y^2 = x^3 + 2x + 26z^5 over field `F_{p^7} = F_p[z]/(z^7 - 2z - 5)`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticCurve<F> {
    /// The x-coordinate of an elliptic curve point.
    pub x: SepticExtension<F>,
    /// The y-coordinate of an elliptic curve point.
    pub y: SepticExtension<F>,
}

impl<F: Field> SepticCurve<F> {
    /// Returns the dummy point.
    #[must_use]
    pub fn dummy() -> Self {
        Self {
            x: SepticExtension::from_base_fn(|i| {
                F::from_canonical_u32(F::CURVE_WITNESS_DUMMY_POINT_X[i])
            }),
            y: SepticExtension::from_base_fn(|i| {
                F::from_canonical_u32(F::CURVE_WITNESS_DUMMY_POINT_Y[i])
            }),
        }
    }

    /// Check if a `SepticCurve` struct is on the elliptic curve.
    pub fn check_on_point(&self) -> bool {
        self.y.square() == Self::curve_formula(self.x)
    }

    /// Negates a `SepticCurve` point.
    #[must_use]
    pub fn neg(&self) -> Self {
        SepticCurve {
            x: self.x,
            y: -self.y,
        }
    }

    #[must_use]
    /// Adds two elliptic curve points, assuming that the addition doesn't lead to the exception cases of weierstrass addition.
    pub fn add_incomplete(&self, other: SepticCurve<F>) -> Self {
        let slope = (other.y - self.y) / (other.x - self.x);
        let result_x = slope.square() - self.x - other.x;
        let result_y = slope * (self.x - result_x) - self.y;
        Self {
            x: result_x,
            y: result_y,
        }
    }

    /// Add assigns an elliptic curve point, assuming that the addition doesn't lead to the exception cases of weierstrass addition.
    pub fn add_assign(&mut self, other: SepticCurve<F>) {
        let result = self.add_incomplete(other);
        self.x = result.x;
        self.y = result.y;
    }

    #[must_use]
    /// Double the elliptic curve point.
    pub fn double(&self) -> Self {
        let slope = F::curve_slope(self);
        let result_x = slope.square() - self.x * F::TWO;
        let result_y = slope * (self.x - result_x) - self.y;
        Self {
            x: result_x,
            y: result_y,
        }
    }

    /// Subtracts two elliptic curve points, assuming that the subtraction doesn't lead to the exception cases of weierstrass addition.
    #[must_use]
    pub fn sub_incomplete(&self, other: SepticCurve<F>) -> Self {
        self.add_incomplete(other.neg())
    }

    /// Subtract assigns an elliptic curve point, assuming that the subtraction doesn't lead to the exception cases of weierstrass addition.
    pub fn sub_assign(&mut self, other: SepticCurve<F>) {
        let result = self.add_incomplete(other.neg());
        self.x = result.x;
        self.y = result.y;
    }
}

impl<F: FieldAlgebra + Any> SepticCurve<F> {
    /// Evaluates the curve formula x^3 + 2x + 26z^5
    pub fn curve_formula(x: SepticExtension<F>) -> SepticExtension<F> {
        if same_field::<F, BabyBear, 4>() {
            babybear::curve_formula(x)
        } else if same_field::<F, KoalaBear, 4>() {
            koalabear::curve_formula(x)
        } else if same_field::<F, Mersenne31, 3>() {
            mersenne31::curve_formula(x)
        } else {
            panic!("Unsupported field type");
        }
    }
}

impl<F: PrimeField32 + FieldBehavior> SepticCurve<F> {
    /// Lift an x coordinate into an elliptic curve.
    /// As an x-coordinate may not be a valid one, we allow an additional value in `[0, 256)` to the hash input.
    /// Also, we always return the curve point with y-coordinate within `[1, (p-1)/2]`, where p is the characteristic.
    /// The returned values are the curve point, the offset used, and the hash input and output.
    pub fn lift_x(m: SepticExtension<F>) -> (Self, u8, [F; 16], [F; 16]) {
        for offset in 0..=255 {
            let m_trial = [
                m.0[0],
                m.0[1],
                m.0[2],
                m.0[3],
                m.0[4],
                m.0[5],
                m.0[6],
                F::from_canonical_u8(offset),
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
                F::ZERO,
            ];

            let m_hash = match F::field_type() {
                FieldType::TypeBabyBear => {
                    let perm = crate::configs::stark_config::BabyBearPoseidon2::init();
                    perm.permute(
                        m_trial.map(|x| BabyBear::from_canonical_u32(x.as_canonical_u32())),
                    )
                    .map(|x| F::from_canonical_u32(x.as_canonical_u32()))
                }
                FieldType::TypeKoalaBear => {
                    let perm = crate::configs::stark_config::KoalaBearPoseidon2::init();
                    perm.permute(
                        m_trial.map(|x| KoalaBear::from_canonical_u32(x.as_canonical_u32())),
                    )
                    .map(|x| F::from_canonical_u32(x.as_canonical_u32()))
                }
                FieldType::TypeMersenne31 => {
                    let perm = crate::configs::stark_config::M31Poseidon2::init();
                    perm.permute(
                        m_trial.map(|x| Mersenne31::from_canonical_u32(x.as_canonical_u32())),
                    )
                    .map(|x| F::from_canonical_u32(x.as_canonical_u32()))
                }
                _ => unimplemented!("Unsupported field type"),
            };

            let x_trial = SepticExtension(m_hash[..7].try_into().unwrap());

            let y_sq = Self::curve_formula(x_trial);
            if let Some(y) = y_sq.sqrt() {
                if y.is_exception() {
                    continue;
                }
                if y.is_send() {
                    return (Self { x: x_trial, y: -y }, offset, m_trial, m_hash);
                }
                return (Self { x: x_trial, y }, offset, m_trial, m_hash);
            }
        }
        panic!("curve point couldn't be found after 256 attempts");
    }
}

impl<F: FieldAlgebra + Any> SepticCurve<F> {
    /// Given three points p1, p2, p3, the function is zero if and only if p3.x == (p1 + p2).x assuming that p1 != p2.
    pub fn sum_checker_x(
        p1: SepticCurve<F>,
        p2: SepticCurve<F>,
        p3: SepticCurve<F>,
    ) -> SepticExtension<F> {
        (p1.x.clone() + p2.x.clone() + p3.x) * (p2.x.clone() - p1.x.clone()).square()
            - (p2.y - p1.y).square()
    }

    /// Given three points p1, p2, p3, the function is zero if and only if p3.y == (p1 + p2).y assuming that p1 != p2.
    pub fn sum_checker_y(
        p1: SepticCurve<F>,
        p2: SepticCurve<F>,
        p3: SepticCurve<F>,
    ) -> SepticExtension<F> {
        (p1.y.clone() + p3.y.clone()) * (p2.x.clone() - p1.x.clone())
            - (p2.y - p1.y.clone()) * (p1.x - p3.x)
    }
}

impl<T> SepticCurve<T> {
    /// Convert a `SepticCurve<S>` into `SepticCurve<T>`, with a map that implements `FnMut(S) -> T`.
    pub fn convert<S: Copy, G: FnMut(S) -> T>(point: SepticCurve<S>, mut f: G) -> Self {
        SepticCurve {
            x: SepticExtension(point.x.0.map(&mut f)),
            y: SepticExtension(point.y.0.map(&mut f)),
        }
    }
}

/// A septic elliptic curve point on y^2 = x^3 + 2x + 26z^5 over field `F_{p^7} = F_p[z]/(z^7 - 2z - 5)`, including the point at infinity.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SepticCurveComplete<T> {
    /// The point at infinity.
    Infinity,
    /// The affine point which can be represented with a `SepticCurve<T>` structure.
    Affine(SepticCurve<T>),
}

impl<F: Field> Add for SepticCurveComplete<F> {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        if self.is_infinity() {
            return rhs;
        }
        if rhs.is_infinity() {
            return self;
        }
        let point1 = self.point();
        let point2 = rhs.point();
        if point1.x != point2.x {
            return Self::Affine(point1.add_incomplete(point2));
        }
        if point1.y == point2.y {
            return Self::Affine(point1.double());
        }
        Self::Infinity
    }
}

impl<F: Field> SepticCurveComplete<F> {
    /// Returns whether or not the point is a point at infinity.
    pub fn is_infinity(&self) -> bool {
        match self {
            Self::Infinity => true,
            Self::Affine(_) => false,
        }
    }

    /// Asserts that the point is not a point at infinity, and returns the `SepticCurve` value.
    pub fn point(&self) -> SepticCurve<F> {
        match self {
            Self::Infinity => panic!("point() called for point at infinity"),
            Self::Affine(point) => *point,
        }
    }
}
