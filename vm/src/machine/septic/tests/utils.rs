use super::super::{config::*, SepticCurve, SepticCurveComplete, SepticExtension};
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra, PrimeField32};
use p3_maybe_rayon::prelude::*;
use rayon_scan::ScanParallelIterator;
use std::time::Instant;

pub fn test_ext_mul<F: FieldAlgebra>() {
    let a: SepticExtension<F> = SepticExtension::from_canonical_u32(1);
    let b: SepticExtension<F> = SepticExtension::from_canonical_u32(2);
    let c = a * b;
    println!("{c}");
}

pub fn test_ext_inv<F: Field>() {
    for i in 0..256 {
        let a: SepticExtension<F> = SepticExtension([
            F::from_canonical_u32(i + 3),
            F::from_canonical_u32(2 * i + 6),
            F::from_canonical_u32(5 * i + 17),
            F::from_canonical_u32(6 * i + 91),
            F::from_canonical_u32(8 * i + 37),
            F::from_canonical_u32(11 * i + 35),
            F::from_canonical_u32(14 * i + 33),
        ]);
        let b = a.inv();
        assert_eq!(a * b, SepticExtension::<F>::ONE);
    }
}

pub fn test_ext_legendre<F: Field>() {
    let a: SepticExtension<F> = SepticExtension::GENERATOR;
    let mut b = SepticExtension::<F>::ONE;
    for i in 1..256 {
        b *= a;
        let (_, c) = b.is_square();
        assert!(c == (i % 2 == 0));
    }
}

pub fn test_ext_sqrt<F: Field>() {
    for i in 0..256 {
        let a: SepticExtension<F> = SepticExtension([
            F::from_canonical_u32(i + 3),
            F::from_canonical_u32(2 * i + 6),
            F::from_canonical_u32(5 * i + 17),
            F::from_canonical_u32(6 * i + 91),
            F::from_canonical_u32(8 * i + 37),
            F::from_canonical_u32(11 * i + 35),
            F::from_canonical_u32(14 * i + 33),
        ]);
        let b = a * a;
        let recovered_a = b.sqrt().unwrap();
        assert_eq!(recovered_a * recovered_a, b);
    }
    let mut b = SepticExtension::<F>::ONE;
    for i in 1..256 {
        let a: SepticExtension<F> = SepticExtension::GENERATOR;
        b *= a;
        let c = b.sqrt();
        if i % 2 == 1 {
            assert!(c.is_none());
        } else {
            let c = c.unwrap();
            assert_eq!(c * c, b);
        }
    }
}

pub fn test_ext_z_pow_p<F: Field>(z: SepticExtension<F>) {
    let p = F::order().to_u32_digits();
    assert_eq!(p.len(), 1);
    let mut p = p[0];
    println!("p = {p}");

    let mut acc = z;
    let mut z_pow_p = SepticExtension::<F>::ONE;
    loop {
        if p == 0 {
            break;
        }
        if p & 1 == 1 {
            z_pow_p *= acc;
        }

        acc = acc.square();
        p >>= 1;
    }

    print!("z_pow_p = {z_pow_p:?}");
    assert_eq!(z_pow_p, SepticExtension::<F>::z_pow_p(1));
}

pub fn test_ext_z_pow_p2<F: Field>(z: SepticExtension<F>) {
    let p = F::order().to_u32_digits();
    assert_eq!(p.len(), 1);
    let p = p[0] as u64;
    let mut p2 = p * p;
    println!("p2 = {p2}");

    let mut acc = z;
    let mut z_pow_p2 = SepticExtension::<F>::ONE;
    loop {
        if p2 == 0 {
            break;
        }
        if p2 & 1 == 1 {
            z_pow_p2 *= acc;
        }

        acc = acc.square();
        p2 >>= 1;
    }

    print!("z_pow_p2 = {z_pow_p2:?}");
    assert_eq!(z_pow_p2, SepticExtension::<F>::z_pow_p2(1));
}

pub fn test_ext_z_pow_exp<F: Field>() {
    let x = SepticExtension::<F>::z_pow_p(1);
    let mut y = x;
    for i in 2..7 {
        let new_y = y * x;
        assert_eq!(new_y, SepticExtension::<F>::z_pow_p(i));
        y = new_y;
    }

    let x = SepticExtension::<F>::z_pow_p2(1);
    let mut y = x;
    for i in 2..7 {
        let new_y = y * x;
        assert_eq!(new_y, SepticExtension::<F>::z_pow_p2(i));
        y = new_y;
    }
}

pub fn test_curve_double<F: PrimeField32>(x: SepticExtension<F>) {
    let (curve_point, _, _, _) = SepticCurve::<F>::lift_x(x);
    let double_point = curve_point.double();
    assert!(double_point.check_on_point());
}

pub fn test_curve_lift_x<F: PrimeField32>(x: SepticExtension<F>) {
    let (curve_point, _, _, _) = SepticCurve::<F>::lift_x(x);
    assert!(curve_point.check_on_point());
    assert!(curve_point.x.is_receive());
}

pub fn test_const_points<F: Field>() {
    [
        [CURVE_WITNESS_DUMMY_POINT_X, CURVE_WITNESS_DUMMY_POINT_Y],
        [CURVE_CUMULATIVE_SUM_START_X, CURVE_CUMULATIVE_SUM_START_Y],
        [DIGEST_SUM_START_X, DIGEST_SUM_START_Y],
    ]
    .iter()
    .for_each(|[x, y]| {
        let x: SepticExtension<F> = SepticExtension::from_base_fn(|i| F::from_canonical_u32(x[i]));
        let y: SepticExtension<F> = SepticExtension::from_base_fn(|i| F::from_canonical_u32(y[i]));
        let point = SepticCurve { x, y };
        assert!(point.check_on_point());
    });
}

pub fn test_curve_simple_sum<F: PrimeField32>() {
    const D: u32 = 1 << 16;
    let mut vec = Vec::with_capacity(D as usize);
    let mut sum = Vec::with_capacity(D as usize);
    let start = Instant::now();
    for i in 0..D {
        let x: SepticExtension<F> = SepticExtension::from_base_slice(&[
            F::from_canonical_u32(i + 25),
            F::from_canonical_u32(2 * i + 376),
            F::from_canonical_u32(4 * i + 23),
            F::from_canonical_u32(8 * i + 531),
            F::from_canonical_u32(16 * i + 542),
            F::from_canonical_u32(32 * i + 196),
            F::from_canonical_u32(64 * i + 667),
        ]);
        let (curve_point, _, _, _) = SepticCurve::<F>::lift_x(x);
        vec.push(curve_point);
    }
    println!("Time elapsed: {:?}", start.elapsed());
    let start = Instant::now();
    for i in 0..D {
        sum.push(vec[i as usize].add_incomplete(vec[((i + 1) % D) as usize]));
    }
    println!("Time elapsed: {:?}", start.elapsed());
    let start = Instant::now();
    for i in 0..(D as usize) {
        assert!(
            SepticCurve::<F>::sum_checker_x(vec[i], vec[(i + 1) % D as usize], sum[i])
                == SepticExtension::<F>::ZERO
        );
        assert!(
            SepticCurve::<F>::sum_checker_y(vec[i], vec[(i + 1) % D as usize], sum[i])
                == SepticExtension::<F>::ZERO
        );
    }
    println!("Time elapsed: {:?}", start.elapsed());
}

pub fn test_curve_parallel_sum<F: PrimeField32>() {
    const D: u32 = 1 << 20;
    let mut vec = Vec::with_capacity(D as usize);
    let start = Instant::now();
    for i in 0..D {
        let x: SepticExtension<F> = SepticExtension::from_base_slice(&[
            F::from_canonical_u32(i + 25),
            F::from_canonical_u32(2 * i + 376),
            F::from_canonical_u32(4 * i + 23),
            F::from_canonical_u32(8 * i + 531),
            F::from_canonical_u32(16 * i + 542),
            F::from_canonical_u32(32 * i + 196),
            F::from_canonical_u32(64 * i + 667),
        ]);
        let (curve_point, _, _, _) = SepticCurve::<F>::lift_x(x);
        vec.push(SepticCurveComplete::Affine(curve_point));
    }
    println!("Time elapsed: {:?}", start.elapsed());

    let mut cum_sum = SepticCurveComplete::Infinity;
    let start = Instant::now();
    for point in &vec {
        cum_sum = cum_sum + *point;
    }
    println!("Time elapsed: {:?}", start.elapsed());
    let start = Instant::now();
    let par_sum = vec
        .into_par_iter()
        .with_min_len(1 << 16)
        .scan(|a, b| *a + *b, SepticCurveComplete::Infinity)
        .collect::<Vec<SepticCurveComplete<F>>>();
    println!("Time elapsed: {:?}", start.elapsed());
    assert_eq!(cum_sum, *par_sum.last().unwrap());
}
