//! BLS12-381 G2 affine addition and doubling: the curve $y^2 = x^3 + 4(u + 1)$ over
//! $\mathbb{F}_{p^2} = \mathbb{F}_p[u]/(u^2 + 1)$. A point in guest memory is `x.c0 || x.c1 ||
//! y.c0 || y.c1`, each coordinate 48 little-endian canonical bytes: 24 dwords, read as four
//! 6-dword field elements.
//!
//! The chips divide in $\mathbb{F}_{p^2}$ through the norm: $1/d = \bar d / N(d)$ with
//! $N(d) = d_0^2 + d_1^2$, which is zero only for $d = 0$ because $-1$ is not a square mod $p$
//! ($p \equiv 3 \bmod 4$). So the inverse of the norm also proves $d \ne 0$.

pub mod add;
pub mod cols;
pub mod double;

use crate::chips::gadgets::{
    curves::weierstrass::bls381::Bls381BaseField,
    utils::{field_params::FieldParameters, polynomial::Polynomial},
};
use num::{BigUint, Zero};

/// Dwords in a G2 point: four 48-byte coordinates.
pub const G2_POINT_DWORDS: usize = 24;
/// Bytes in a G2 point.
pub const G2_POINT_BYTES: u32 = 192;
/// Dwords in one coordinate.
pub const FP_DWORDS: usize = 6;

/// An $\mathbb{F}_{p^2}$ element `(c0, c1)`, each reduced.
pub type Fp2 = [BigUint; 2];

fn modulus() -> BigUint {
    Bls381BaseField::modulus()
}

fn sub(a: &BigUint, b: &BigUint) -> BigUint {
    let p = modulus();
    (a + &p - b % &p) % &p
}

fn fp2_mul(a: &Fp2, b: &Fp2) -> Fp2 {
    let p = modulus();
    [
        sub(&(&a[0] * &b[0] % &p), &(&a[1] * &b[1] % &p)),
        (&a[0] * &b[1] + &a[1] * &b[0]) % &p,
    ]
}

fn fp2_sub(a: &Fp2, b: &Fp2) -> Fp2 {
    [sub(&a[0], &b[0]), sub(&a[1], &b[1])]
}

/// `n / d`, or `None` for `d = 0`.
fn fp2_div(n: &Fp2, d: &Fp2) -> Option<Fp2> {
    let p = modulus();
    let norm = (&d[0] * &d[0] + &d[1] * &d[1]) % &p;
    if norm.is_zero() {
        return None;
    }
    let norm_inv = norm.modpow(&(&p - 2u32), &p);
    let conj = [d[0].clone(), sub(&BigUint::zero(), &d[1])];
    let inv = [&conj[0] * &norm_inv % &p, &conj[1] * &norm_inv % &p];
    Some(fp2_mul(n, &inv))
}

/// `(x3, y3)` from the slope through `(x1, y1)`: `x3 = λ² - x1 - x2`, `y3 = λ(x1 - x3) - y1`.
fn from_slope(lambda: &Fp2, x1: &Fp2, y1: &Fp2, x2: &Fp2) -> [BigUint; 4] {
    let x3 = fp2_sub(&fp2_sub(&fp2_mul(lambda, lambda), x1), x2);
    let y3 = fp2_sub(&fp2_mul(lambda, &fp2_sub(x1, &x3)), y1);
    [x3[0].clone(), x3[1].clone(), y3[0].clone(), y3[1].clone()]
}

/// `p + q` for affine points with `p.x != q.x`; `None` otherwise, which the chip cannot prove.
pub fn g2_add(p: &[BigUint; 4], q: &[BigUint; 4]) -> Option<[BigUint; 4]> {
    let (px, py) = ([p[0].clone(), p[1].clone()], [p[2].clone(), p[3].clone()]);
    let (qx, qy) = ([q[0].clone(), q[1].clone()], [q[2].clone(), q[3].clone()]);
    let lambda = fp2_div(&fp2_sub(&qy, &py), &fp2_sub(&qx, &px))?;
    Some(from_slope(&lambda, &px, &py, &qx))
}

/// `2p` for an affine point with `p.y != 0`; `None` otherwise, which the chip cannot prove.
pub fn g2_double(p: &[BigUint; 4]) -> Option<[BigUint; 4]> {
    let modulus = modulus();
    let (x, y) = ([p[0].clone(), p[1].clone()], [p[2].clone(), p[3].clone()]);
    let x_sq = fp2_mul(&x, &x);
    let three_x_sq = [&x_sq[0] * 3u32 % &modulus, &x_sq[1] * 3u32 % &modulus];
    let two_y = [&y[0] * 2u32 % &modulus, &y[1] * 2u32 % &modulus];
    let lambda = fp2_div(&three_x_sq, &two_y)?;
    Some(from_slope(&lambda, &x, &y, &x))
}

/// The four coordinates of a point from its 24 dwords.
pub fn point_from_dwords(dwords: &[u64]) -> [BigUint; 4] {
    assert_eq!(dwords.len(), G2_POINT_DWORDS);
    core::array::from_fn(|i| {
        let bytes: Vec<u8> = dwords[i * FP_DWORDS..(i + 1) * FP_DWORDS]
            .iter()
            .flat_map(|d| d.to_le_bytes())
            .collect();
        BigUint::from_bytes_le(&bytes)
    })
}

/// The 24 dwords of a point.
pub fn point_to_dwords(point: &[BigUint; 4]) -> Vec<u64> {
    point
        .iter()
        .flat_map(|c| {
            let mut bytes = c.to_bytes_le();
            assert!(
                bytes.len() <= FP_DWORDS * 8,
                "coordinate wider than 48 bytes"
            );
            bytes.resize(FP_DWORDS * 8, 0);
            bytes
                .as_chunks::<8>()
                .0
                .iter()
                .map(|b| u64::from_le_bytes(*b))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Whether every coordinate is below the modulus, as the chips require of their inputs.
pub fn is_canonical(point: &[BigUint; 4]) -> bool {
    let p = modulus();
    point.iter().all(|c| c < &p)
}

/// `p + q` as the syscall computes it, refusing what the chip cannot prove: a coordinate not
/// below the modulus, or `p.x == q.x`.
pub fn g2_add_checked(p: &[BigUint; 4], q: &[BigUint; 4]) -> [BigUint; 4] {
    assert!(
        is_canonical(p) && is_canonical(q),
        "G2 add: a coordinate is not below the modulus"
    );
    g2_add(p, q).expect("G2 add: p.x == q.x; double p, or the sum is the point at infinity")
}

/// `2p` as the syscall computes it, refusing what the chip cannot prove: a coordinate not below
/// the modulus, or `p.y == 0`.
pub fn g2_double_checked(p: &[BigUint; 4]) -> [BigUint; 4] {
    assert!(
        is_canonical(p),
        "G2 double: a coordinate is not below the modulus"
    );
    g2_double(p).expect("G2 double: p.y == 0")
}

/// The four coordinates of a point from its byte limbs, as polynomials.
pub(crate) fn coords<E: Clone>(limbs: Vec<E>) -> [Polynomial<E>; 4] {
    assert_eq!(limbs.len(), G2_POINT_BYTES as usize);
    core::array::from_fn(|i| Polynomial::from_coefficients(&limbs[i * 48..(i + 1) * 48]))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The G2 generator as `x.c0, x.c1, y.c0, y.c1` (big-endian hex, from the IETF/zcash
    /// encodings).
    pub(crate) fn generator() -> [BigUint; 4] {
        let h = |s: &str| BigUint::parse_bytes(s.as_bytes(), 16).unwrap();
        [
            h("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"),
            h("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"),
            h("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"),
            h("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"),
        ]
    }

    fn on_curve(pt: &[BigUint; 4]) -> bool {
        let m = modulus();
        let (x, y) = (
            [pt[0].clone(), pt[1].clone()],
            [pt[2].clone(), pt[3].clone()],
        );
        let lhs = fp2_mul(&y, &y);
        let x3 = fp2_mul(&fp2_mul(&x, &x), &x);
        let b = [BigUint::from(4u32), BigUint::from(4u32)];
        let rhs = [(&x3[0] + &b[0]) % &m, (&x3[1] + &b[1]) % &m];
        lhs == rhs
    }

    #[test]
    fn add_and_double_agree_and_stay_on_the_curve() {
        let g = generator();
        assert!(on_curve(&g));
        let g2 = g2_double(&g).unwrap();
        let g3 = g2_add(&g2, &g).unwrap();
        let g4a = g2_double(&g2).unwrap();
        let g4b = g2_add(&g3, &g).unwrap();
        assert_eq!(g4a, g4b);
        for pt in [&g2, &g3, &g4a] {
            assert!(on_curve(pt));
            assert!(is_canonical(pt));
        }
        assert_eq!(point_from_dwords(&point_to_dwords(&g3)), g3);
        // equal x is refused: P + P and P + (-P)
        assert!(g2_add(&g, &g).is_none());
        let neg = [
            g[0].clone(),
            g[1].clone(),
            sub(&BigUint::zero(), &g[2]),
            sub(&BigUint::zero(), &g[3]),
        ];
        assert!(g2_add(&g, &neg).is_none());
    }
}
