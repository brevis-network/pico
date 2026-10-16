use crate::emulator::AotEmulatorCore;
use hashbrown::HashMap;
use k256::{elliptic_curve::ff::PrimeField, FieldBytes, FieldElement, Scalar as K256Scalar};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use pico_vm::{
    chips::gadgets::{
        curves::weierstrass::bls381::Bls381BaseField, utils::field_params::FieldParameters,
    },
    emulator::riscv::hook::ed_decompress::hint_ed_decompress,
};

pub type Hook = fn(&AotEmulatorCore, &[u8]) -> Vec<Vec<u8>>;

const SECP256K1_ECRECOVER: u32 = 5;
pub const FD_EDDECOMPRESS: u32 = 8;
pub const FD_FP_SQRT: u32 = 10;
pub const FD_FP_INV: u32 = 11;
pub const FD_BLS12_381_SQRT: u32 = 12;
pub const FD_BLS12_381_INVERSE: u32 = 13;

pub fn default_hook_map() -> HashMap<u32, Hook> {
    let hooks: [(u32, Hook); _] = [
        (SECP256K1_ECRECOVER, ecrecover),
        (FD_EDDECOMPRESS, ed_decompress),
        (FD_FP_SQRT, hook_fp_sqrt),
        (FD_FP_INV, hook_fp_inverse),
        (FD_BLS12_381_SQRT, hook_bls12_381_sqrt),
        (FD_BLS12_381_INVERSE, hook_bls12_381_inverse),
    ];
    HashMap::from_iter(hooks)
}

const NQR: [u8; 32] = {
    let mut nqr = [0; 32];
    nqr[31] = 3;
    nqr
};

const NQR_BLS12_381: [u8; 48] = {
    let mut nqr = [0; 48];
    nqr[47] = 2;
    nqr
};

fn pad_to_be(val: &BigUint, len: usize) -> Vec<u8> {
    let mut bytes = val.to_bytes_le();
    bytes.resize(len, 0);
    bytes.reverse();
    bytes
}

pub fn ecrecover(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    if buf.len() != 65 {
        return vec![vec![0]];
    }

    let r_is_y_odd = buf[0] & 0b1000_0000 != 0;

    let r_bytes: [u8; 32] = buf[1..33].try_into().unwrap();
    let alpha_bytes: [u8; 32] = buf[33..65].try_into().unwrap();

    let r = FieldElement::from_bytes(&FieldBytes::from(r_bytes)).unwrap();
    let alpha = FieldElement::from_bytes(&FieldBytes::from(alpha_bytes)).unwrap();

    if bool::from(r.is_zero()) || bool::from(alpha.is_zero()) {
        return vec![vec![0]];
    }

    if let Some(mut y_coord) = alpha.sqrt().into_option().map(|y| y.normalize()) {
        let r = K256Scalar::from_repr(r.to_bytes()).unwrap();
        let r_inv = r.invert().expect("Non zero r scalar");

        if r_is_y_odd != bool::from(y_coord.is_odd()) {
            y_coord = y_coord.negate(1);
            y_coord = y_coord.normalize();
        }

        vec![
            vec![1],
            y_coord.to_bytes().to_vec(),
            r_inv.to_bytes().to_vec(),
        ]
    } else {
        let nqr_field = FieldElement::from_bytes(&FieldBytes::from(NQR)).unwrap();
        let qr = alpha * nqr_field;
        let root = qr
            .sqrt()
            .expect("if alpha is not a square, then qr should be a square");

        vec![vec![0], root.to_bytes().to_vec()]
    }
}

/// The interpreter's hint, called rather than copied.
///
/// This used to be a copy, and it kept the 32-byte request of the protocol that predates the RV64
/// guest patch, which moved the guest to 64 bytes (compressed point || `v`). Every request then
/// failed to parse and came back "not decompressable" without the two witnesses the guest reads
/// next, so an ed25519 guest that ran under the interpreter stopped on missing input under AOT.
#[must_use]
pub fn ed_decompress(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    hint_ed_decompress(buf)
}

pub fn hook_fp_inverse(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

    assert!(buf.len() == 4 + 2 * len, "FpOp Hook: Invalid buffer length");

    let buf = &buf[4..];
    let element = BigUint::from_bytes_be(&buf[..len]);
    let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);

    assert!(!element.is_zero(), "FpOp: Inverse called with zero");

    let inverse = element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

    vec![pad_to_be(&inverse, len)]
}

pub fn hook_fp_sqrt(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    let len: usize = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;

    assert!(buf.len() == 4 + 3 * len, "FpOp Hook: Invalid buffer length");

    let buf = &buf[4..];
    let element = BigUint::from_bytes_be(&buf[..len]);
    let modulus = BigUint::from_bytes_be(&buf[len..2 * len]);
    let nqr = BigUint::from_bytes_be(&buf[2 * len..3 * len]);

    assert!(
        element < modulus,
        "Element is not less than modulus, the hook only accepts canonical representations"
    );
    assert!(
        nqr < modulus,
        "NQR is zero or non-canonical, the hook only accepts canonical representations"
    );

    if element.is_zero() {
        return vec![vec![1], vec![0; len]];
    }

    if let Some(root) = sqrt_fp(&element, &modulus, &nqr) {
        vec![vec![1], pad_to_be(&root, len)]
    } else {
        let qr = (&nqr * &element) % &modulus;
        let root = sqrt_fp(&qr, &modulus, &nqr).unwrap();

        vec![vec![0], pad_to_be(&root, len)]
    }
}

fn sqrt_fp(element: &BigUint, modulus: &BigUint, nqr: &BigUint) -> Option<BigUint> {
    if modulus % BigUint::from(4u64) == BigUint::from(3u64) {
        let maybe_root = element.modpow(
            &((modulus + BigUint::from(1u64)) / BigUint::from(4u64)),
            modulus,
        );

        return Some(maybe_root).filter(|root| root * root % modulus == *element);
    }

    tonelli_shanks(element, modulus, nqr)
}

#[allow(clippy::many_single_char_names)]
fn tonelli_shanks(element: &BigUint, modulus: &BigUint, nqr: &BigUint) -> Option<BigUint> {
    if legendre_symbol(element, modulus) != BigUint::one() {
        return None;
    }

    let mut s = BigUint::zero();
    let mut q = modulus - BigUint::one();
    while &q % &BigUint::from(2u64) == BigUint::zero() {
        s += BigUint::from(1u64);
        q /= BigUint::from(2u64);
    }

    let z = nqr;
    let mut c = z.modpow(&q, modulus);
    let mut r = element.modpow(&((&q + BigUint::from(1u64)) / BigUint::from(2u64)), modulus);
    let mut t = element.modpow(&q, modulus);
    let mut m = s;

    while t != BigUint::one() {
        let mut i = BigUint::zero();
        let mut tt = t.clone();
        while tt != BigUint::one() {
            tt = &tt * &tt % modulus;
            i += BigUint::from(1u64);

            if i == m {
                return None;
            }
        }

        let b_pow = BigUint::from(2u64).pow((&m - &i - BigUint::from(1u64)).try_into().unwrap());
        let b = c.modpow(&b_pow, modulus);

        r = &r * &b % modulus;
        c = &b * &b % modulus;
        t = &t * &c % modulus;
        m = i;
    }

    Some(r)
}

fn legendre_symbol(element: &BigUint, modulus: &BigUint) -> BigUint {
    assert!(!element.is_zero(), "FpOp: Legendre symbol of zero called.");

    element.modpow(&((modulus - BigUint::one()) / BigUint::from(2u64)), modulus)
}

pub fn hook_bls12_381_sqrt(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    assert!(buf.len() == 48, "BLS12-381 sqrt input must be 48 bytes");

    let field_element = BigUint::from_bytes_be(buf);

    if field_element.is_zero() {
        return vec![vec![1], vec![0; 48]];
    }

    let modulus = BigUint::from_bytes_le(Bls381BaseField::MODULUS);
    let exp = (&modulus + BigUint::from(1u64)) / BigUint::from(4u64);
    let sqrt = field_element.modpow(&exp, &modulus);

    let square = (&sqrt * &sqrt) % &modulus;
    if square != field_element {
        let nqr = BigUint::from_bytes_be(&NQR_BLS12_381);
        let qr = (&nqr * &field_element) % &modulus;
        let root = qr.modpow(&exp, &modulus);

        assert!((&root * &root) % &modulus == qr, "NQR sanity check failed");

        return vec![vec![0], pad_to_be(&root, 48)];
    }

    vec![vec![1], pad_to_be(&sqrt, 48)]
}

pub fn hook_bls12_381_inverse(_: &AotEmulatorCore, buf: &[u8]) -> Vec<Vec<u8>> {
    assert!(buf.len() == 48, "BLS12-381 inverse input must be 48 bytes");

    let field_element = BigUint::from_bytes_be(buf);
    assert!(
        !field_element.is_zero(),
        "Field element is the additive identity"
    );

    let modulus = BigUint::from_bytes_le(Bls381BaseField::MODULUS);
    let inverse = field_element.modpow(&(&modulus - BigUint::from(2u64)), &modulus);

    vec![pad_to_be(&inverse, 48)]
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        panic::{catch_unwind, AssertUnwindSafe},
        sync::Arc,
    };

    use num_bigint::BigUint;
    use num_traits::{One, Zero};
    use p3_koala_bear::KoalaBear;
    use pico_vm::{
        chips::gadgets::{
            curves::edwards::{
                ed25519::{Ed25519BaseField, Ed25519Parameters},
                EdwardsParameters,
            },
            utils::field_params::FieldParameters,
        },
        compiler::riscv::program::Program,
        emulator::{
            opts::EmulatorOpts,
            riscv::{hook as interpreter_hook, riscv_emulator::RiscvEmulator},
        },
    };

    use super::{
        default_hook_map, pad_to_be, FD_BLS12_381_INVERSE, FD_BLS12_381_SQRT, FD_EDDECOMPRESS,
        FD_FP_INV, FD_FP_SQRT, SECP256K1_ECRECOVER,
    };
    use crate::emulator::AotEmulatorCore;

    #[test]
    fn phase5_default_hook_map_matches_baseline_fd_surface() {
        let hook_map = default_hook_map();

        for fd in [
            5,
            FD_EDDECOMPRESS,
            FD_FP_SQRT,
            FD_FP_INV,
            FD_BLS12_381_SQRT,
            FD_BLS12_381_INVERSE,
        ] {
            assert!(hook_map.contains_key(&fd), "missing hook fd {fd}");
        }
    }

    /// Every hook answers exactly what the interpreter's hook on the same fd answers.
    ///
    /// The guest decides how many values to read next from a hook's answer, so a hook that
    /// answers differently here sends the guest down a different path under AOT than under the
    /// interpreter. The other hooks in this file are still copies of the interpreter's, which is
    /// how `ed_decompress` drifted unnoticed: the test above only checks that each fd is served.
    #[test]
    fn every_hook_answers_what_the_interpreter_hook_does() {
        let program = test_program();
        let aot = AotEmulatorCore::new(program.clone(), Vec::new());
        let interpreter =
            RiscvEmulator::new_single::<KoalaBear>(program, EmulatorOpts::default(), None);

        let aot_hooks = default_hook_map();
        let interpreter_hooks = interpreter_hook::default_hook_map();
        let requests = requests();

        let mut served: Vec<u32> = aot_hooks.keys().copied().collect();
        served.sort_unstable();
        let mut served_by_interpreter: Vec<u32> = interpreter_hooks.keys().copied().collect();
        served_by_interpreter.sort_unstable();
        assert_eq!(
            served, served_by_interpreter,
            "the two emulators serve different hook fds"
        );
        let mut covered: Vec<u32> = requests.iter().map(|(fd, _)| *fd).collect();
        covered.sort_unstable();
        assert_eq!(covered, served, "every served fd needs requests here");

        for (fd, requests) in &requests {
            for (i, buf) in requests.iter().enumerate() {
                let from_aot = catch_unwind(AssertUnwindSafe(|| aot_hooks[fd](&aot, buf)));
                let from_interpreter = catch_unwind(AssertUnwindSafe(|| {
                    interpreter_hooks[fd](&interpreter, buf)
                }));
                match (from_aot, from_interpreter) {
                    (Ok(a), Ok(b)) => assert_eq!(a, b, "fd {fd}, request {i}: the answers differ"),
                    // A request the interpreter refuses must be refused here too.
                    (Err(_), Err(_)) => {}
                    (a, b) => panic!(
                        "fd {fd}, request {i}: only one hook panicked (AOT: {}, interpreter: {})",
                        a.is_err(),
                        b.is_err()
                    ),
                }
            }
        }
    }

    /// What the hook the AOT runtime serves on `FD_EDDECOMPRESS` answers, as a guest's write to
    /// that fd would ask it.
    fn ask(buf: &[u8]) -> Vec<Vec<u8>> {
        let emu = AotEmulatorCore::new(test_program(), Vec::new());
        default_hook_map()[&FD_EDDECOMPRESS](&emu, buf)
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The Ed25519 basepoint, compressed, followed by its `v = d*y^2 + 1`: decompressable, so the
    /// whole answer is `[[1]]`.
    #[test]
    fn ed_decompress_answers_one_for_the_basepoint() {
        let buf = unhex(concat!(
            "5866666666666666666666666666666666666666666666666666666666666666",
            "7a2e8b682f9896d01bc89acdc0628fe1fa19fc3762aedb4fd9a2708c1dac164e",
        ));
        assert_eq!(ask(&buf), vec![vec![1]]);
    }

    /// `y = 2` is the smallest canonical `y` off the curve. The answer carries the two witnesses
    /// the guest checks, byte for byte what the interpreter's hook answers for the same request.
    #[test]
    fn ed_decompress_answers_zero_with_witnesses_off_the_curve() {
        let buf = unhex(concat!(
            "0200000000000000000000000000000000000000000000000000000000000000",
            "b3e2654d2837add7ad6207053529c00160a2e7dde5011d33cef9bfadb8b30d48",
        ));
        let v_inv = unhex("3651c90543fd9fdbaa1718094ddb713267c14fe8d62d9ac9da9f3bd745045a75");
        let root = unhex("12602e991ffb040ef76aac57d447726fac039ca99b8cb989e67ec816ef37ba3e");
        assert_eq!(ask(&buf), vec![vec![0], v_inv.clone(), root.clone()]);

        // And they are witnesses, not just the pinned bytes: `v_inv * v == 1` and
        // `root^2 == 2 * u * v_inv` with `u = y^2 - 1`.
        let p = Ed25519BaseField::modulus();
        let le = BigUint::from_bytes_le;
        let (y, v) = (le(&buf[..32]), le(&buf[32..]));
        let (v_inv, root) = (le(&v_inv), le(&root));
        assert_eq!((&v * &v_inv) % &p, BigUint::from(1u32));
        let u = (&y * &y + &p - BigUint::from(1u32)) % &p;
        assert_eq!((&root * &root) % &p, (BigUint::from(2u32) * u * v_inv) % &p);
    }

    /// `y = p` reduces to a point on the curve, but the chip constrains `y < p`: not
    /// decompressable, and no witnesses follow.
    #[test]
    fn ed_decompress_answers_zero_for_a_non_canonical_y() {
        let buf = unhex(concat!(
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0100000000000000000000000000000000000000000000000000000000000000",
        ));
        assert_eq!(ask(&buf), vec![vec![0]]);
    }

    /// The older protocol wrote the compressed point alone. Answering it would hand a guest built
    /// against one protocol the hints of the other.
    #[test]
    #[should_panic(expected = "FD_EDDECOMPRESS expects 64 bytes")]
    fn ed_decompress_rejects_a_32_byte_request() {
        let buf = unhex("5866666666666666666666666666666666666666666666666666666666666666");
        let _ = ask(&buf);
    }

    fn test_program() -> Arc<Program> {
        let mut program = Program::new(Vec::new(), 0x1000, 0x1000);
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    /// Requests that take each hook down each of its branches, and a malformed one each.
    fn requests() -> Vec<(u32, Vec<Vec<u8>>)> {
        vec![
            (SECP256K1_ECRECOVER, ecrecover_requests()),
            (FD_EDDECOMPRESS, ed_decompress_requests()),
            (FD_FP_SQRT, fp_sqrt_requests()),
            (FD_FP_INV, fp_inverse_requests()),
            (FD_BLS12_381_SQRT, bls12_381_requests()),
            (FD_BLS12_381_INVERSE, bls12_381_requests()),
        ]
    }

    /// `flags || r || alpha`, where the top bit of `flags` asks for an odd `y`.
    fn ecrecover_requests() -> Vec<Vec<u8>> {
        let p = secp256k1_prime();
        // The secp256k1 generator's x, so `x^3 + 7` is a square.
        let x = BigUint::parse_bytes(
            b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            16,
        )
        .unwrap();
        let alpha = (x.pow(3) + 7u32) % &p;
        // 3 is the hooks' non-residue, so this one is not a square.
        let non_square = (&alpha * 3u32) % &p;
        let request = |flags: u8, alpha: &BigUint| {
            let mut buf = vec![flags];
            buf.extend(pad_to_be(&x, 32));
            buf.extend(pad_to_be(alpha, 32));
            buf
        };
        vec![
            request(0, &alpha),
            request(0x80, &alpha),
            request(0, &non_square),
            request(0, &BigUint::zero()),
            vec![0; 64],
        ]
    }

    fn secp256k1_prime() -> BigUint {
        BigUint::parse_bytes(
            b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
            16,
        )
        .unwrap()
    }

    /// The compressed point, then the guest's `v = d*y^2 + 1`.
    fn ed_decompress_requests() -> Vec<Vec<u8>> {
        let modulus = Ed25519BaseField::modulus();
        let request = |y: &BigUint, negative: bool| {
            let v =
                ((y * y) % &modulus * Ed25519Parameters::d_biguint() + BigUint::one()) % &modulus;
            let mut buf = y.to_bytes_le();
            buf.resize(32, 0);
            if negative {
                buf[31] |= 0x80;
            }
            let mut v = v.to_bytes_le();
            v.resize(32, 0);
            buf.extend(v);
            buf
        };
        let (_, basepoint_y) = Ed25519Parameters::generator();
        vec![
            request(&basepoint_y, false),
            request(&basepoint_y, true),
            // Not on the curve: answered with the two witnesses the guest checks.
            request(&BigUint::from(2u32), false),
            // Not canonical.
            request(&modulus, false),
            // The request of the protocol before the RV64 guest patch.
            vec![0; 32],
        ]
    }

    /// `len || element || modulus`, then `nqr` for a square root, each big-endian in `len` bytes.
    fn fp_request(len: usize, values: &[&BigUint]) -> Vec<u8> {
        let mut buf = (len as u32).to_be_bytes().to_vec();
        for value in values {
            buf.extend(pad_to_be(value, len));
        }
        buf
    }

    /// 23 and the secp256k1 prime are 3 mod 4, 17 and 2^255 - 19 are 1 mod 4, which takes the two
    /// square-root algorithms. The 32-byte requests are there for byte order, which a one-byte
    /// request cannot show.
    fn fp_sqrt_requests() -> Vec<Vec<u8>> {
        let n = |x: u32| BigUint::from(x);
        let secp256k1 = secp256k1_prime();
        let ed25519 = Ed25519BaseField::modulus();
        vec![
            fp_request(1, &[&n(4), &n(23), &n(5)]),
            fp_request(1, &[&n(5), &n(23), &n(5)]),
            fp_request(1, &[&n(0), &n(23), &n(5)]),
            fp_request(1, &[&n(4), &n(17), &n(3)]),
            fp_request(1, &[&n(3), &n(17), &n(3)]),
            // 3 is a non-residue mod the secp256k1 prime, so 12 is not a square; 2 is one mod
            // 2^255 - 19.
            fp_request(32, &[&n(4), &secp256k1, &n(3)]),
            fp_request(32, &[&n(12), &secp256k1, &n(3)]),
            fp_request(32, &[&n(4), &ed25519, &n(2)]),
            fp_request(32, &[&n(2), &ed25519, &n(2)]),
            // Not canonical, then truncated.
            fp_request(1, &[&n(23), &n(23), &n(5)]),
            vec![0, 0, 0, 1, 4, 23],
        ]
    }

    fn fp_inverse_requests() -> Vec<Vec<u8>> {
        let n = |x: u32| BigUint::from(x);
        vec![
            fp_request(1, &[&n(5), &n(23)]),
            fp_request(32, &[&n(5), &secp256k1_prime()]),
            fp_request(1, &[&n(0), &n(23)]),
            vec![0, 0, 0, 1, 5],
        ]
    }

    /// A 48-byte big-endian element.
    fn bls12_381_requests() -> Vec<Vec<u8>> {
        let element = |x: u8| {
            let mut buf = vec![0u8; 48];
            buf[47] = x;
            buf
        };
        vec![element(4), element(5), element(0), vec![0; 47]]
    }
}
