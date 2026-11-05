//! Reference vectors for the GPU extension-field benchmark.
//!
//! Writes `<out_dir>/kb{4,5,8}_mul.bin` with random `a`, `b` and the Plonky3 product `a * b`, so
//! pico-gpu's `src/field/test/ext_bench.cu` can check its KoalaBear^5 / ^8 arithmetic
//! against Plonky3 before timing it.
//!
//!   cargo run --release -p pico-mle-core --example e3_ext_vectors -- <out_dir> [n]
//!
//! File layout (little-endian u32): `n`, `d`, then `a[n*d]`, `b[n*d]`, `c[n*d]`, every value a
//! canonical field element in Plonky3's basis (`a = sum_i a[i] * X^i`).
//!
//! Fields:
//! - kb4: `BinomialExtensionField<KoalaBear, 4>` = F[X]/(X^4 - 3), the production challenge field.
//! - kb5: `QuinticTrinomialExtensionField<KoalaBear>` = F[X]/(X^5 + X^2 - 1).
//! - kb8: `BinomialExtensionField<KoalaBear, 8>` = F[Y]/(Y^8 - 3).

use std::{fs::File, io::Write, path::PathBuf};

use p3_field::{
    extension::{BinomialExtensionField, QuinticTrinomialExtensionField},
    BasedVectorSpace, PrimeCharacteristicRing, PrimeField32,
};
use p3_koala_bear::KoalaBear;

type F = KoalaBear;

fn random_f() -> F {
    // Uniform enough for test vectors: rejection keeps it exactly uniform.
    loop {
        let x = rand::random::<u32>() & 0x7fff_ffff;
        if x < F::ORDER_U32 {
            return F::new(x);
        }
    }
}

fn write_vectors<E>(path: PathBuf, n: usize)
where
    E: BasedVectorSpace<F> + Copy + core::ops::Mul<Output = E>,
{
    let d = E::DIMENSION;
    let rand_e = || E::from_basis_coefficients_fn(|_| random_f());
    let a: Vec<E> = (0..n).map(|_| rand_e()).collect();
    let b: Vec<E> = (0..n).map(|_| rand_e()).collect();
    let c: Vec<E> = a.iter().zip(&b).map(|(x, y)| *x * *y).collect();

    let mut f = File::create(&path).expect("create vector file");
    f.write_all(&(n as u32).to_le_bytes()).unwrap();
    f.write_all(&(d as u32).to_le_bytes()).unwrap();
    for v in [&a, &b, &c] {
        for e in v.iter() {
            for coef in e.as_basis_coefficients_slice() {
                f.write_all(&coef.as_canonical_u32().to_le_bytes()).unwrap();
            }
        }
    }
    println!("wrote {} (n={n}, d={d})", path.display());
}

fn main() {
    let mut args = std::env::args().skip(1);
    let out = PathBuf::from(args.next().expect("usage: e3_ext_vectors <out_dir> [n]"));
    let n: usize = args
        .next()
        .map(|s| s.parse().expect("n"))
        .unwrap_or(1 << 16);
    std::fs::create_dir_all(&out).expect("create out dir");

    // Sanity: the quintic really is X^5 = 1 - X^2 in Plonky3's basis.
    let x = QuinticTrinomialExtensionField::<F>::from_basis_coefficients_fn(|i| {
        if i == 1 {
            F::ONE
        } else {
            F::ZERO
        }
    });
    let x5 = x * x * x * x * x;
    let expect = QuinticTrinomialExtensionField::<F>::from_basis_coefficients_fn(|i| match i {
        0 => F::ONE,
        2 => F::NEG_ONE,
        _ => F::ZERO,
    });
    assert_eq!(x5, expect, "quintic reduction identity");

    write_vectors::<BinomialExtensionField<F, 4>>(out.join("kb4_mul.bin"), n);
    write_vectors::<QuinticTrinomialExtensionField<F>>(out.join("kb5_mul.bin"), n);
    write_vectors::<BinomialExtensionField<F, 8>>(out.join("kb8_mul.bin"), n);
}
